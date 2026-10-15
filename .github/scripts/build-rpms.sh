#!/bin/bash
# Build the confluent rpms whose spec depends on the target distribution:
# confluent_vtbufferd (arch-specific) and, unless --arch-only is given, the
# noarch client, server and imgutil. Runs inside an EL or openSUSE container.
#
# Usage: build-rpms.sh [--arch-only]
set -e

cd "$(dirname "$0")/../.."

if command -v zypper > /dev/null; then
    zypper -n install --no-recommends rpm-build gcc make git-core tar xz pandoc systemd python3 python3-setuptools
    # the buildrpm scripts stage into ~/rpmbuild, SUSE defaults to /usr/src/packages
    echo "%_topdir $HOME/rpmbuild" >> ~/.rpmmacros
else
    dnf -y --setopt=install_weak_deps=False install epel-release
    dnf -y --setopt=install_weak_deps=False install rpm-build gcc make git-core tar xz pandoc systemd python3 python3-setuptools
fi
git config --global --add safe.directory "$PWD"
./mkversion
mkdir -p ~/rpmbuild/SOURCES ~/rpmbuild/SPECS

# the buildrpm scripts hide rpmbuild's output, so on failure rerun the spec
# they wrote to show why
build() {
    "$1/buildrpm" && return 0
    spec=~/rpmbuild/SPECS/$(basename "$1").spec
    [ -f "$spec" ] && rpmbuild -ba "$spec"
    return 1
}

build confluent_vtbufferd
if [ "$1" != "--arch-only" ]; then
    build confluent_client
    build confluent_server
    # imgutil/buildrpm calls rpmbuild directly, so its output is visible
    ./imgutil/buildrpm
fi
