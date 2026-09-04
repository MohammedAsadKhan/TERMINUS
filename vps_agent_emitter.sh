#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# AgentSOC Remote VPS Threat Emitter / Integration Script
# Deploy on any remote Linux VPS (AWS, DigitalOcean, Linode, Hetzner)
# ─────────────────────────────────────────────────────────────────

# Set AGENTSOC_URL to your public domain/ngrok URL or IP (e.g. http://203.0.113.50:8000)
AGENTSOC_URL="${AGENTSOC_URL:-http://localhost:8000}"
ORG_ID="${ORG_ID:-org-O7M9c8qz2Hk}"
AUTH_TOKEN="${AUTH_TOKEN:-tok-xnOqeD3D}"

echo "=========================================================="
echo "  🌐 Remote VPS Threat Emitter -> Target: $AGENTSOC_URL   "
echo "=========================================================="

send_alert() {
    local rule_id="$1"
    local level="$2"
    local desc="$3"
    local mitre="$4"
    local alert_id="vps-alert-$(date +%s)"

    payload=$(cat <<EOF
{
  "id": "$alert_id",
  "rule": {
    "id": $rule_id,
    "level": $level,
    "description": "$desc",
    "mitre": { "id": "$mitre" }
  },
  "agent": {
    "id": "vps-external-01",
    "name": "vps-remote-attacker-target.cloud"
  },
  "data": {
    "srcip": "$(curl -s ifconfig.me || echo '198.51.100.44')",
    "command": "remote execution payload",
    "user": "root"
  },
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "location": "remote-vps-sensor"
}
EOF
)

    echo "[VPS -> AgentSOC] Sending Alert: $desc (Level $level, MITRE $mitre)..."
    curl -s -X POST "$AGENTSOC_URL/wazuh" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "X-Org-ID: $ORG_ID" \
        -d "$payload"
    echo ""
}

# Example High-Threat Events Sent From Remote VPS:
send_alert 92010 14 "Ransomware shadow copy deletion attempt detected on VPS" "T1490"
send_alert 92055 13 "Remote LSASS process memory dump attempt via comsvcs" "T1003"
send_alert 5712  11 "SSH Brute-Force attack detected targeting root on VPS" "T1110"
