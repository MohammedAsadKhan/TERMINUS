# File name: http.py
# Author: Team LARP
# Date: 2026-11-19 (comments revised)
# Version: 0.1.0
# Purpose: Create shared HTTP clients for outbound integration requests.

from __future__ import annotations

import socket

import httpx2


def create_async_client() -> httpx2.AsyncClient:
    """Build a pooled async HTTP/2 client with bounded connect, read, write and pool
    timeouts and three transport retries.
    """
    limits = httpx2.Limits(
        max_connections=200, max_keepalive_connections=40, keepalive_expiry=30.0
    )
    timeout = httpx2.Timeout(connect=5.0, read=30.0, write=10.0, pool=10.0)
    transport = httpx2.AsyncHTTPTransport(
        http2=True,
        retries=3,
        limits=limits,
        socket_options=[(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)],
    )
    return httpx2.AsyncClient(
        transport=transport, timeout=timeout, follow_redirects=True
    )


def create_client() -> httpx2.Client:
    """Build the synchronous equivalent of the async client, with the same pooling,
    timeouts and retries.
    """
    limits = httpx2.Limits(
        max_connections=200, max_keepalive_connections=40, keepalive_expiry=30.0
    )
    timeout = httpx2.Timeout(connect=5.0, read=30.0, write=10.0, pool=10.0)
    transport = httpx2.HTTPTransport(
        http2=True,
        retries=3,
        limits=limits,
        socket_options=[(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)],
    )
    return httpx2.Client(transport=transport, timeout=timeout, follow_redirects=True)
