# File: observer/Dockerfile
# Author: Team LARP
# Revision date: 2026-11-12
# Version: 0.1.0
# Purpose: Independent SSH and nftables observer for the disposable response lab.

FROM alpine:3.20

RUN apk add --no-cache \
        ca-certificates \
        netcat-openbsd \
        openssh-client \
        python3

COPY entrypoint.sh /entrypoint.sh
COPY observe.py /opt/lab/observe.py
RUN chmod 0755 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["sleep", "infinity"]
