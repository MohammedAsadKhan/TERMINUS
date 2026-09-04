from __future__ import annotations

import socket

import httpx2


def create_async_client() -> httpx2.AsyncClient:
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
