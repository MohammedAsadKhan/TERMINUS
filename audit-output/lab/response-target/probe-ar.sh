#!/bin/sh
IFS= read -r payload
printf '%s\n' "$payload" > /tmp/terminus-ar-probe.json
exit 0