#!/bin/bash
# File: attacker/entrypoint.sh
# Author: Team LARP
# Revision date: 2026-11-12
# Version: 0.1.0
# Purpose: Start the key-only probe sshd on the attacker host.

set -euo pipefail

install -d -m 0700 -o probe -g probe /home/probe/.ssh
install -m 0600 -o probe -g probe /run/lab-keys/id_ed25519.pub /home/probe/.ssh/authorized_keys

rm -f /etc/ssh/ssh_host_*_key*
install -m 0600 -o root -g root /run/lab-hostkeys/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key
ssh-keygen -y -f /etc/ssh/ssh_host_ed25519_key > /etc/ssh/ssh_host_ed25519_key.pub
chmod 0644 /etc/ssh/ssh_host_ed25519_key.pub
install -d -m 0755 /run/sshd

/usr/sbin/sshd -D -e &
ssh_pid=$!
trap 'kill "$ssh_pid" 2>/dev/null || true' TERM INT
wait "$ssh_pid"
