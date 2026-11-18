#!/bin/bash
# File: target/entrypoint.sh
# Author: Team LARP
# Revision date: 2026-11-14
# Version: 0.1.0
# Purpose: Start the disposable SSH/Wazuh target and bounded owned-table cleanup.

set -euo pipefail

# The public key arrives from a generated, git-ignored lab key pair.
install -d -m 0700 -o labadmin -g labadmin /home/labadmin/.ssh
install -m 0600 -o labadmin -g labadmin /run/lab-keys/id_ed25519.pub /home/labadmin/.ssh/authorized_keys

# Pin the disposable host identity so the observer's known_hosts stays valid
# across container restarts that reuse the same .state directory.
rm -f /etc/ssh/ssh_host_*_key*
install -m 0600 -o root -g root /run/lab-hostkeys/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key
ssh-keygen -y -f /etc/ssh/ssh_host_ed25519_key > /etc/ssh/ssh_host_ed25519_key.pub
chmod 0644 /etc/ssh/ssh_host_ed25519_key.pub
install -d -m 0755 /run/sshd

# Install the shipped endpoint command without editing the repository copy.
# The checkout stores the script with CRLF endings; normalize them at install
# time so the "#!/usr/bin/python3" shebang stays executable (a trailing CR makes
# exec fail with ENOENT). The command is root-owned; Wazuh execd runs it as root.
sed 's/\r$//' /opt/terminus/terminus_ip_block.py > /usr/local/sbin/terminus-ip-block
chown root:root /usr/local/sbin/terminus-ip-block
chmod 0755 /usr/local/sbin/terminus-ip-block
install -m 0750 -o root -g wazuh /usr/local/sbin/terminus-ip-block /var/ossec/active-response/bin/terminus-ip-block

# Render the lab manager address into the minimal agent configuration.
sed "s/__WAZUH_MANAGER__/${WAZUH_MANAGER:-wazuh.manager}/g" /opt/lab/ossec.conf > /var/ossec/etc/ossec.conf
chown root:wazuh /var/ossec/etc/ossec.conf
chmod 0640 /var/ossec/etc/ossec.conf

if [ ! -f /var/ossec/etc/client.keys ]; then
    install -m 0640 -o root -g wazuh /dev/null /var/ossec/etc/client.keys
fi
chown root:wazuh /var/ossec/etc/client.keys
chmod 0640 /var/ossec/etc/client.keys

# sshd must log through syslog, not stderr, so its own "Failed password" and
# "Invalid user" lines land in /var/log/auth.log. The Wazuh sshd decoder needs
# those lines to emit rule 5710 with the sshd/authentication_failed groups the
# Terminus live-response path matches on; PAM-only lines produce rule 5503.
/usr/sbin/rsyslogd
/usr/sbin/sshd -D &
ssh_pid=$!

# Start the agent after sshd so local log collection begins immediately.
/var/ossec/bin/wazuh-control start || true

# Kernel TTL restores access even if this loop stops. The loop only removes
# empty tables with the exact identity comment and known lab structure; it
# cannot create a block or extend a timeout.
cleanup_loop() {
    while sleep 30; do
        /usr/local/sbin/terminus-ip-block --cleanup-expired || true
    done
}
cleanup_loop &
cleanup_pid=$!

trap 'kill "$ssh_pid" "$cleanup_pid" 2>/dev/null || true; /var/ossec/bin/wazuh-control stop >/dev/null 2>&1 || true' TERM INT
wait "$ssh_pid"
