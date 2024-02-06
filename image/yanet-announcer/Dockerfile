FROM yanetplatform/yanet AS yanet
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    iproute2 \
    bird2

COPY --from=yanet /usr/bin/yanet-cli /usr/bin/yanet-cli
COPY yanet-announcer.py /usr/bin/yanet-announcer
