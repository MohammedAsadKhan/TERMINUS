"""Sandboxed repository cloning, URL validation, and safe static file traversal."""

from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

_DEFAULT_ALLOWLIST_HOSTS = {"github.com", "gitlab.com"}
_MAX_CLONE_BYTES = 200 * 1024 * 1024  # 200 MB
_MAX_FILE_BYTES = 1 * 1024 * 1024     # 1 MB
_CLONE_TIMEOUT_SECONDS = 120


class SandboxSecurityError(ValueError):
    """Raised when repository locator or cloning violates sandboxing boundaries."""


def is_local_path_locator(locator: str) -> bool:
    """True only for bare filesystem paths or ``file://`` URLs - never for remote clone URLs.

    A locator with any ``://`` scheme other than ``file://`` (http, https, ssh, git, ...)
    and scp-style SSH locators (``git@host:path``) are remote and must go through full
    URL validation even in local mode.
    """
    if locator.lower().startswith("file://"):
        return True
    if "://" in locator:
        return False
    # scp-style SSH locator: "user@host:path" - the head before the first ':' contains '@'
    return "@" not in locator.split(":", 1)[0]


def validate_clone_url(url: str) -> None:
    """Enforce strict URL security policy: https only, allowlisted host, no SSRF, no credentials."""
    if not url or not url.strip():
        raise SandboxSecurityError("Repository URL cannot be empty")

    url = url.strip()
    allow_local = (
        os.getenv("TERMINUS_DEPLOYMENT_MODE") == "local"
        and os.getenv("TERMINUS_REPO_SCAN_ALLOW_LOCAL") == "true"
    )

    # Local escape hatch for tests/local fixtures: bare filesystem paths and file://
    # URLs only. Remote URLs are never exempt - they always run the full checks below.
    if allow_local and is_local_path_locator(url):
        return

    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https":
        raise SandboxSecurityError(f"Protocol '{parsed.scheme}' not allowed; must use 'https://'")

    if parsed.username is not None or parsed.password is not None:
        raise SandboxSecurityError("Embedded credentials in repository URL are prohibited")

    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        raise SandboxSecurityError("Repository URL missing hostname")

    # Reject localhost, link-local, loopback, private IPv4/IPv6
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise SandboxSecurityError(f"Destination IP '{hostname}' is not permitted (SSRF protection)")
    except ValueError:
        # Hostname is not an IP literal; verify against allowed hosts
        if hostname in ("localhost", "127.0.0.1", "::1"):
            raise SandboxSecurityError("Localhost destination is not permitted")

        allowlist = set(_DEFAULT_ALLOWLIST_HOSTS)
        custom_hosts = os.getenv("TERMINUS_REPO_ALLOWLIST_HOSTS")
        if custom_hosts:
            allowlist.update(h.strip().lower() for h in custom_hosts.split(",") if h.strip())

        if hostname not in allowlist:
            raise SandboxSecurityError(
                f"Host '{hostname}' is not in the repository allowlist ({', '.join(sorted(allowlist))})"
            )


def _get_dir_size(path: Path) -> int:
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            fp = os.path.join(root, f)
            try:
                total += os.path.getsize(fp)
            except OSError:
                pass
    return total


@contextmanager
def clone_repository(
    url: str,
    commit_sha: str | None = None,
    depth: int = 500,
    timeout_seconds: int = _CLONE_TIMEOUT_SECONDS,
) -> Iterator[tuple[Path, str]]:
    """Clone a repository into a temporary directory under strict process isolation.

    Yields (clone_path, current_commit_sha).
    """
    validate_clone_url(url)
    temp_dir = Path(tempfile.mkdtemp(prefix="terminus-repo-scan-"))

    try:
        allow_local = (
            os.getenv("TERMINUS_DEPLOYMENT_MODE") == "local"
            and os.getenv("TERMINUS_REPO_SCAN_ALLOW_LOCAL") == "true"
        )
        file_protocol = "always" if allow_local else "never"

        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_CONFIG_NOSYSTEM"] = "1"

        clone_cmd = [
            "git",
            "-c", "core.hooksPath=",
            "-c", f"protocol.file.allow={file_protocol}",
            "clone",
            "--depth", str(depth),
            "--no-tags",
            "--single-branch",
            "--no-recurse-submodules",
            url,
            str(temp_dir),
        ]

        try:
            res = subprocess.run(
                clone_cmd,
                capture_output=True,
                text=True,
                env=env,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise SandboxSecurityError(f"Clone timed out after {timeout_seconds} seconds") from None

        if res.returncode != 0:
            raise SandboxSecurityError(f"git clone failed: {res.stderr.strip()[:300]}")

        # Check total size
        size = _get_dir_size(temp_dir)
        if size > _MAX_CLONE_BYTES:
            raise SandboxSecurityError(f"Cloned repository size ({size} bytes) exceeds {int(_MAX_CLONE_BYTES / 1024 / 1024)}MB limit")

        # Get current HEAD commit sha
        sha_cmd = ["git", "-C", str(temp_dir), "rev-parse", "HEAD"]
        sha_res = subprocess.run(sha_cmd, capture_output=True, text=True, check=False)
        head_sha = sha_res.stdout.strip() if sha_res.returncode == 0 else (commit_sha or "unknown")

        yield temp_dir, head_sha

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def safe_walk_files(root: Path) -> Iterator[tuple[str, Path]]:
    """Yield relative file paths and resolved Path objects, skipping symlink escapes and files > 1MB."""
    resolved_root = root.resolve()

    for dirpath, dirnames, filenames in os.walk(root):
        # Don't recurse into .git directory
        if ".git" in dirnames:
            dirnames.remove(".git")

        for name in filenames:
            file_path = Path(dirpath) / name
            try:
                resolved_file = file_path.resolve()
            except (OSError, RuntimeError):
                continue

            # Symlink / path traversal check
            if not resolved_file.is_relative_to(resolved_root):
                continue

            # File size limit
            try:
                if resolved_file.stat().st_size > _MAX_FILE_BYTES:
                    continue
            except OSError:
                continue

            # Relative path from root
            rel_path = file_path.relative_to(root).as_posix()
            yield rel_path, resolved_file
