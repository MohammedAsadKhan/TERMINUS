# File: target/Dockerfile
# Author: Team LARP
# Revision date: 2026-11-12
# Version: 0.1.0
# Purpose: Ubuntu SSH endpoint with nftables and a Wazuh 4.x agent for the response lab.

FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG WAZUH_AGENT_VERSION=4.14.10-1
ARG WAZUH_MANAGER=wazuh.manager

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        iproute2 \
        netcat-openbsd \
        nftables \
        openssh-server \
        procps \
        python3 \
        rsyslog \
        sudo \
    && rm -rf /var/lib/apt/lists/*

# Wazuh 4.x APT repository, following the official Linux agent installation
# guide: https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html
RUN install -d -m 0755 /usr/share/keyrings \
    && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
    && chmod 0644 /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update \
    && WAZUH_MANAGER="${WAZUH_MANAGER}" apt-get install -y --no-install-recommends "wazuh-agent=${WAZUH_AGENT_VERSION}" \
    && rm -rf /var/lib/apt/lists/* \
    && sed -i "s/^deb /#deb /" /etc/apt/sources.list.d/wazuh.list

# The management account is key-only. Sudo is limited to read-only nftables
# inspection so the independent observer can read the owned set without
# receiving firewall-write or arbitrary shell privilege.
RUN useradd --create-home --shell /bin/bash labadmin \
    && passwd -l labadmin \
    && install -d -m 0700 -o labadmin -g labadmin /home/labadmin/.ssh \
    && printf '%s\n' \
        'labadmin ALL=(root) NOPASSWD: /usr/sbin/nft --json list tables, /usr/sbin/nft --json list table inet terminus_*' \
        > /etc/sudoers.d/labadmin-nft \
    && chmod 0440 /etc/sudoers.d/labadmin-nft \
    && visudo -cf /etc/sudoers.d/labadmin-nft

COPY sshd_config /etc/ssh/sshd_config.d/10-response-lab.conf
COPY ossec.conf /opt/lab/ossec.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh \
    && touch /var/log/auth.log \
    && chown syslog:adm /var/log/auth.log

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
