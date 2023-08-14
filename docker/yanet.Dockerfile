FROM yanetplatform/builder AS builder

COPY . /project
RUN meson setup --prefix=/target build
RUN meson compile -C build
RUN meson install -C build


FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    iproute2

RUN mkdir -p /run/yanet

COPY --from=builder /target /target
