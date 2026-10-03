#!/bin/sh
# Reference sources for the port: NetBird at the version running on the router, plus every Go dependency (vendor/).
set -eu
TAG=v0.79.0
dir=$(cd "$(dirname "$0")/.." && pwd)/upstream
mkdir -p "$dir"
[ -d "$dir/netbird/.git" ] || git clone -q --depth 1 --branch "$TAG" https://github.com/netbirdio/netbird "$dir/netbird"
cd "$dir/netbird" && go mod vendor
