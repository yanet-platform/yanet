#!/bin/bash

output="packages"
release="22.04"
version="64.0.0"

usage() {
    echo "Usage: $0 [ -o ARTIFACTS_DIR ] [ -r RELEASE ] [ -v VERSION ] -t package|image"
}

while getopts ":ho:r:t:v:" option; do
    case "${option}" in
    h)
        usage
        exit 0
        ;;
    o) output=${OPTARG} ;;
    r) release=${OPTARG} ;;
    t) type=${OPTARG} ;;
    v) version=${OPTARG} ;;
    esac
done

subversions=(${version//./ })

if [ "${type}" = "package" ]; then
    git submodule update --init --recursive

    docker build -t yanet-deb-package:${version} \
        --build-arg RELEASE=${release} \
        --build-arg YANET_VERSION_MAJOR=${subversions[0]} \
        --build-arg YANET_VERSION_MINOR=${subversions[1]} \
        --build-arg YANET_VERSION_REVISION=${subversions[2]} \
        --build-arg YANET_VERSION_CUSTOM=${release} \
        --network host \
        -f build/Dockerfile.debian-package .

    mkdir -p ${output}
    docker run --rm --tty --volume $(realpath -- ${output}):/build \
        yanet-deb-package:${version} sh -c 'find /opt -type f -maxdepth 1 -exec cp {} /build/ \;'

elif [ "${type}" = "image" ]; then
    git submodule update --init --recursive

    docker build -t yanet:${version} \
        --build-arg RELEASE=${release} \
        --build-arg YANET_VERSION_MAJOR=${subversions[0]} \
        --build-arg YANET_VERSION_MINOR=${subversions[1]} \
        --build-arg YANET_VERSION_REVISION=${subversions[2]} \
        --build-arg YANET_VERSION_CUSTOM=${release} \
        --network host \
        -f build/Dockerfile.image .
else
    usage
    exit 1
fi
