FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    iproute2 \
    bird2

COPY yanet-announcer.py /usr/bin/yanet-announcer
