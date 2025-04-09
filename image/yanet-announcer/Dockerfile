FROM yanetplatform/yanet AS yanet
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    iproute2 \
    netbase \
    bird2 \
    libnuma-dev \
    libpcap-dev \
    libatomic1

COPY --from=yanet /usr/bin/yanet-cli /usr/bin/yanet-cli
COPY --from=yanet /usr/bin/yanet-announcer /usr/bin/yanet-announcer

