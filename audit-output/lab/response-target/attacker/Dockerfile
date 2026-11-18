# File: attacker/Dockerfile
# Author: Team LARP
# Revision date: 2026-11-12
# Version: 0.1.0
# Purpose: Attacker and probe host for the disposable SSH response lab.

FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
        netcat-openbsd \
        openssh-client \
        openssh-server \
        procps \
        sshpass \
    && rm -rf /var/lib/apt/lists/*

# probe is key-only and exists so the independent observer can run a TCP probe
# from the attacker's network namespace, matching the Kali management path in
# the original Terminus lab.
RUN useradd --create-home --shell /bin/bash probe \
    && passwd -l probe \
    && install -d -m 0700 -o probe -g probe /home/probe/.ssh

COPY sshd_config /etc/ssh/sshd_config.d/10-attacker-lab.conf
COPY attack.sh /usr/local/bin/attack.sh
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /usr/local/bin/attack.sh /entrypoint.sh

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
