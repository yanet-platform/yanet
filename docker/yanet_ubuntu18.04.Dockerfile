FROM yanetplatform/builder_ubuntu18.04 AS builder

ARG YANET_VERSION_MAJOR
ARG YANET_VERSION_MINOR
ARG YANET_VERSION_REVISION
ARG YANET_VERSION_HASH
ARG YANET_VERSION_CUSTOM

COPY . /project
RUN meson setup --prefix=/target \
                -Dtarget=release \
                -Dyanet_config=release,firewall,l3balancer \
                -Darch=corei7,broadwell,knl \
                -Dversion_major=$YANET_VERSION_MAJOR \
                -Dversion_minor=$YANET_VERSION_MINOR \
                -Dversion_revision=$YANET_VERSION_REVISION \
                -Dversion_hash=$YANET_VERSION_HASH \
                -Dversion_custom=$YANET_VERSION_CUSTOM \
                build_release

RUN meson compile -C build_release
RUN meson install -C build_release


FROM ubuntu:18.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    iproute2 \
    ibverbs-providers \
    libibverbs-dev

RUN mkdir -p /run/yanet

COPY --from=builder /target/bin/* /usr/bin/
