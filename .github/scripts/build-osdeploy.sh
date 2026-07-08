#!/bin/bash
# Build the confluent_osdeploy rpm like confluent_osdeploy/buildrpm does, but
# using pre-built utils binaries (from CI artifacts) instead of compiling them
# in local podman containers (el9build/el7build).
#
# Usage: build-osdeploy.sh <x86_64|aarch64> <el8utils-dir> <el9utils-dir>
set -e

ARCH=$1
EL8UTILS=$(readlink -f "$2")
EL9UTILS=$(readlink -f "$3")
UTILBINS="confluent_imginfo copernicus clortho autocons start_root urlmount"

cd "$(dirname "$0")/../.."

VERSION=$(git describe|cut -d- -f 1)
NUMCOMMITS=$(git describe|cut -d- -f 2)
if [ "$NUMCOMMITS" != "$VERSION" ]; then
    LASTNUM=$(echo $VERSION|rev|cut -d . -f 1|rev)
    LASTNUM=$((LASTNUM+1))
    FIRSTPART=$(echo $VERSION|rev|cut -d . -f 2-|rev)
    VERSION=${FIRSTPART}.${LASTNUM}
    VERSION=$VERSION~dev$NUMCOMMITS+$(git describe|cut -d- -f 3)
fi

if [ "$ARCH" = "aarch64" ]; then
    SPEC=confluent_osdeploy-aarch64.spec
else
    SPEC=confluent_osdeploy.spec
fi
sed -e "s/#VERSION#/$VERSION/" confluent_osdeploy/${SPEC}.tmpl > confluent_osdeploy/$SPEC

mkdir -p ~/rpmbuild/SOURCES
cp LICENSE confluent_osdeploy/
# The spec's diskless loop expects suse16-diskless, which is not committed to
# git (upstream builds from a working tree that has it). Synthesize it from
# suse15-diskless until upstream adds it, mirroring how the spec synthesizes
# el9 from el8.
if [ ! -d confluent_osdeploy/suse16-diskless ]; then
    cp -a confluent_osdeploy/suse15-diskless confluent_osdeploy/suse16-diskless
fi
tar Jcf ~/rpmbuild/SOURCES/confluent_osdeploy.tar.xz confluent_osdeploy

for gen in el8 el9; do
    utils=$EL8UTILS
    [ "$gen" = el9 ] && utils=$EL9UTILS
    rm -rf ${gen}bin
    mkdir -p ${gen}bin/opt/confluent/bin ${gen}bin/stateless-bin
    for bin in $UTILBINS; do
        [ -f "$utils/$bin" ] || { echo "missing $utils/$bin" >&2; exit 1; }
    done
    cp "$utils"/confluent_imginfo "$utils"/copernicus "$utils"/clortho \
       "$utils"/autocons ${gen}bin/opt/confluent/bin/
    cp "$utils"/start_root "$utils"/urlmount ${gen}bin/stateless-bin/
    # artifact downloads lose the execute bit
    chmod 755 ${gen}bin/opt/confluent/bin/* ${gen}bin/stateless-bin/*
    tar Jcf ~/rpmbuild/SOURCES/confluent_${gen}bin.tar.xz ${gen}bin/
    rm -rf ${gen}bin
done

rpmbuild -ba confluent_osdeploy/$SPEC
