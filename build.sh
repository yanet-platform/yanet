#!/bin/bash
set -euo pipefail

output="packages"
release="24.04"
version=""
type=""

usage() {
	printf 'Usage: %s [ -o ARTIFACTS_DIR ] [ -r RELEASE ] [ -v X.Y.Z ] -t package|image\n' "$0"
	printf '%s\n' 'Defaults: artifacts=packages, Ubuntu=24.04, version=debian/changelog (X.Y-Z -> X.Y.Z).' \
		'Package builds require X.Y.Z to match the changelog package version X.Y-Z.'
}

die() {
	printf 'Error: %s\n' "$*" >&2
	exit 1
}

while getopts ":ho:r:t:v:" option; do
	case "$option" in
	h)
		usage
		exit 0
		;;
	o | r | t | v)
		[[ -n $OPTARG && $OPTARG != -* ]] || die "Option -$option requires a nonempty value, not another option"
		case "$option" in
		o) output=$OPTARG ;;
		r) release=$OPTARG ;;
		t) type=$OPTARG ;;
		v) version=$OPTARG ;;
		esac
		;;
	:) die "Option -$OPTARG requires a value" ;;
	\?) die "Unknown option: -$OPTARG" ;;
	esac
done
shift "$((OPTIND - 1))"
[[ $# -eq 0 ]] || die "Unexpected positional arguments: $*"
[[ $type == package || $type == image ]] || die "Option -t must be package or image (see -h)"

# Use canonical decimal components, without leading zeroes or shell expansion.
number='(0|[1-9][0-9]*)'
version_pattern="^${number}\\.${number}\\.${number}$"
[[ -z $version || $version =~ $version_pattern ]] || die "Version must be X.Y.Z with canonical decimal components"

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
if [[ -z $version || $type == package ]]; then
	changelog="$repo_root/debian/changelog"
	[[ -f $changelog && -r $changelog ]] || die "Cannot read $changelog"
	header=""
	IFS= read -r header <"$changelog" || [[ -n $header ]] || die "Empty changelog: $changelog"
	header_pattern="^yanet \\((${number}\\.${number}-${number})\\) [^[:space:];]+; urgency=[a-z]+$"
	[[ $header =~ $header_pattern ]] || die "Invalid changelog header: expected yanet (X.Y-Z) DISTRIBUTION; urgency=LEVEL"
	package_version=${BASH_REMATCH[1]}
	[[ -n $version ]] || version=${package_version/-/.}
	if [[ $type == package && ${version%.*}-${version##*.} != "$package_version" ]]; then
		die "Version $version does not match changelog package version $package_version"
	fi
fi
IFS=. read -r major minor revision <<<"$version"

git -C "$repo_root" submodule update --init --recursive
version_hash=$(git -C "$repo_root" rev-parse HEAD)

if [[ $type == package ]]; then
	image="yanet-deb-package:$version"
	dockerfile="$repo_root/build/Dockerfile.debian-package"
else
	image="yanet:$version"
	dockerfile="$repo_root/build/Dockerfile.image"
fi

build_args=(
	--build-arg "RELEASE=$release"
	--build-arg "YANET_VERSION_MAJOR=$major"
	--build-arg "YANET_VERSION_MINOR=$minor"
	--build-arg "YANET_VERSION_REVISION=$revision"
	--build-arg "YANET_VERSION_HASH=$version_hash"
	--build-arg "YANET_VERSION_CUSTOM=$release"
	--network host
)
docker build -t "$image" "${build_args[@]}" -f "$dockerfile" "$repo_root"

if [[ $type == package ]]; then
	mkdir -p -- "$output"
	output=$(cd -- "$output" && pwd -P)
	docker run --rm --volume "$output:/build" "$image" \
		sh -c 'find /opt -maxdepth 1 -type f -exec cp -t /build/ -- {} +'
fi
