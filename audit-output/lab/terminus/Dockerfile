# File name: Dockerfile
# Author: Team LARP
# Revision date: 2026-11-13
# Version: 0.1.0
# Purpose: Provide a pinned Python and SSH runtime for the disposable TERMINUS lab.

FROM python:3.12-slim

RUN apt-get update -qq \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends openssh-client \
    && python -m pip install --no-cache-dir uv==0.9.2 \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1
