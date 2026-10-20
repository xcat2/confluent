#!/bin/bash
# Build the confluent_ipxe rpm. The spec repackages the prebuilt boot roms
# that iPXE publishes with each release; rpmbuild does not fetch remote
# sources itself, so download the tarball of the release the spec names.
set -e

cd "$(dirname "$0")/../.."
SPEC=ipxe/confluent_ipxe.spec
VERSION=$(rpmspec -q --srpm --qf '%{version}' $SPEC)
mkdir -p ~/rpmbuild/SOURCES
curl -fsSL -o ~/rpmbuild/SOURCES/ipxeboot.tar.gz \
    "https://github.com/ipxe/ipxe/releases/download/v$VERSION/ipxeboot.tar.gz"
rpmbuild -ba $SPEC
