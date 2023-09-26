FROM ubuntu:22.04


RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    vim \
    curl \
    ca-certificates \
    iproute2 \
    iputils-arping \
    iputils-tracepath \
    iputils-ping

RUN python3 -m pip install python-pytun

COPY tap.py /usr/bin/
