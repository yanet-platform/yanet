FROM yanetplatform/builder AS builder

ARG YANET_VERSION_MAJOR=0
ARG YANET_VERSION_MINOR=0
ARG YANET_VERSION_REVISION=0
ARG YANET_VERSION_HASH=00000000
ARG YANET_VERSION_CUSTOM=develop

COPY . /project
RUN meson setup --prefix=/target \
                -Dtarget=release \
                -Dstrip=true \
                -Dyanet_config=release,firewall,l3balancer,low_memory \
                -Darch=corei7,broadwell,knl \
                -Dversion_major=$YANET_VERSION_MAJOR \
                -Dversion_minor=$YANET_VERSION_MINOR \
                -Dversion_revision=$YANET_VERSION_REVISION \
                -Dversion_hash=$YANET_VERSION_HASH \
                -Dversion_custom=$YANET_VERSION_CUSTOM \
                build_release

RUN meson compile -C build_release
RUN meson install -C build_release


FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    iproute2

COPY --from=builder /target/bin/* /usr/bin/
COPY --from=builder /target/share /usr/share
COPY --from=builder /target/lib /usr/lib
COPY --from=builder /target/include /usr/include
