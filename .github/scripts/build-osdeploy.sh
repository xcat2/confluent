#!/bin/bash
# Build the confluent_osdeploy rpm the way confluent_osdeploy/buildrpm and
# buildrpm-aarch64 do, but from utils binaries built by earlier CI jobs
# (build-utils.sh) instead of compiling them in local podman containers.
#
# Usage: build-osdeploy.sh <x86_64|aarch64> <el8utils-dir> <el9utils-dir>
set -e

ARCH=$1
EL8UTILS=$(readlink -f "$2")
EL9UTILS=$(readlink -f "$3")

cd "$(dirname "$0")/../.."
VERSION=$(./mkversion --tilde)

case "$ARCH" in
x86_64) SPEC=confluent_osdeploy.spec ;;
aarch64) SPEC=confluent_osdeploy-aarch64.spec ;;
*) echo "unknown arch $ARCH" >&2; exit 1 ;;
esac
sed -e "s/#VERSION#/$VERSION/" confluent_osdeploy/$SPEC.tmpl > confluent_osdeploy/$SPEC

mkdir -p ~/rpmbuild/SOURCES
cp LICENSE confluent_osdeploy/
tar Jcf ~/rpmbuild/SOURCES/confluent_osdeploy.tar.xz confluent_osdeploy

for gen in el8 el9; do
    utils=$EL8UTILS
    [ "$gen" = el9 ] && utils=$EL9UTILS
    rm -rf ${gen}bin
    mkdir -p ${gen}bin/opt/confluent/bin ${gen}bin/stateless-bin
    (cd "$utils" && cp confluent_imginfo copernicus clortho autocons "$OLDPWD"/${gen}bin/opt/confluent/bin/)
    (cd "$utils" && cp start_root urlmount "$OLDPWD"/${gen}bin/stateless-bin/)
    # artifact downloads lose the execute bit
    chmod 755 ${gen}bin/opt/confluent/bin/* ${gen}bin/stateless-bin/*
    tar Jcf ~/rpmbuild/SOURCES/confluent_${gen}bin.tar.xz ${gen}bin/
    rm -rf ${gen}bin
done

rpmbuild -ba confluent_osdeploy/$SPEC
