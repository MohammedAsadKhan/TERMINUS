#!/bin/bash
# File: attacker/attack.sh
# Author: Team LARP
# Revision date: 2026-11-12
# Version: 0.1.0
# Purpose: Generate bounded failed SSH password attempts for Wazuh SSH rules.
#
# Usage: attack.sh [attempts] [target-ip]
# The default target is the attack-path address used by the shipped endpoint
# command. Each attempt uses a nonexistent account and a deliberately wrong
# password so sshd emits authentication_failed events.

set -euo pipefail

attempts="${1:-3}"
target="${2:-10.77.0.20}"

case "$attempts" in
    ''|*[!0-9]*) echo "attempt count must be an integer" >&2; exit 2 ;;
esac

i=0
while [ "$i" -lt "$attempts" ]; do
    i=$((i + 1))
    sshpass -p 'wrong-password-for-lab' ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o GlobalKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        -o NumberOfPasswordPrompts=1 \
        -o ConnectTimeout=3 \
        -o LogLevel=ERROR \
        "invalid-lab-user@${target}" true >/dev/null 2>&1 || true
done

echo "completed ${attempts} failed SSH attempt(s) against ${target}"
