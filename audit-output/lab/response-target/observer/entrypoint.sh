#!/bin/sh
# File: observer/entrypoint.sh
# Author: Team LARP
# Revision date: 2026-11-12
# Version: 0.1.0
# Purpose: Prepare the read-only lab key for independent observer commands.

set -eu

# Windows bind mounts do not preserve POSIX modes. Copy the disposable private
# key to container-local storage and enforce the mode SSH requires.
install -m 0600 -o root -g root /run/lab-keys/id_ed25519 /tmp/lab_ed25519

exec "$@"
