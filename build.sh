#!/bin/bash

output="packages"
ubuntu_release="22.04"
yanet_version="64.0.0"

usage() {
    cat <<EOF
Usage:
    $0 [ -o ARTIFACTS_DIR ] [ -u UBUNTU_RELEASE ] [ -y YANET_VERSION ] -t package|image"

Package build:
    $0 -o packages -u 18.04 -y 64.0.0 -t package

    $ ls packages
    yanet_64.0-0_amd64.buildinfo  yanet_64.0-0.tar.gz		   yanet-controlplane-dbgsym_64.0-0_amd64.ddeb	yanet-dataplane-systemd_64.0-0_amd64.deb
    yanet_64.0-0_amd64.changes    yanet-cli_64.0-0_amd64.deb	   yanet-controlplane-systemd_64.0-0_amd64.deb	yanet-dev_64.0-0_amd64.deb
    yanet_64.0-0_amd64.deb	      yanet-cli-dbgsym_64.0-0_amd64.ddeb   yanet-dataplane_64.0-0_amd64.deb		yanet-dev-dbgsym_64.0-0_amd64.ddeb
    yanet_64.0-0.dsc	      yanet-controlplane_64.0-0_amd64.deb  yanet-dataplane-dbgsym_64.0-0_amd64.ddeb	yanet-utils_64.0-0_amd64.deb
builded artifacts will be stored into "packages" directory.

Image build:
    $0 -u 22.04 -y 64.0.0 -t image

    $ docker images | grep ^yanet
    yanet                              64.0.0    c2650e2b4a21   18 seconds ago   203MB
image contains "yanet-dataplane", "yanet-controlplane" and "yanet-cli" binary executable files in directory /usr/bin.

EOF
}

while getopts ":ho:t:u:y:" option; do
    case "${option}" in
    h)
        usage
        exit 0
        ;;
    o) output=${OPTARG} ;;
    t) type=${OPTARG} ;;
    u) ubuntu_release=${OPTARG} ;;
    y) yanet_version=${OPTARG} ;;
    esac
done

yanet_subversions=(${yanet_version//./ })

case "${type}" in
package)
    git submodule update --init --recursive

    docker build -t yanet-deb-package:${yanet_version} \
        --build-arg RELEASE=${ubuntu_release} \
        --build-arg YANET_VERSION_MAJOR=${yanet_subversions[0]} \
        --build-arg YANET_VERSION_MINOR=${yanet_subversions[1]} \
        --build-arg YANET_VERSION_REVISION=${yanet_subversions[2]} \
        --build-arg YANET_VERSION_CUSTOM=${ubuntu_release} \
        --network host \
        -f build/Dockerfile.debian-package .

    mkdir -p ${output}
    docker run --rm --tty --volume $(realpath -- ${output}):/build \
        yanet-deb-package:${yanet_version} sh -c 'find /opt -type f -maxdepth 1 -exec cp {} /build/ \;'
    ;;
image)
    git submodule update --init --recursive

    docker build -t yanet:${yanet_version} \
        --build-arg RELEASE=${ubuntu_release} \
        --build-arg YANET_VERSION_MAJOR=${yanet_subversions[0]} \
        --build-arg YANET_VERSION_MINOR=${yanet_subversions[1]} \
        --build-arg YANET_VERSION_REVISION=${yanet_subversions[2]} \
        --build-arg YANET_VERSION_CUSTOM=${ubuntu_release} \
        --network host \
        -f build/Dockerfile.image .
    ;;
*)
    usage
    exit 1
    ;;
esac
