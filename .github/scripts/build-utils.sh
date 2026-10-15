#!/bin/bash
# Build the confluent_osdeploy utils inside a distro container, standing in for
# the el7build/el8builder/el9build podman images confluent_osdeploy/buildrpm
# uses. The el8bin set is linked against the oldest glibc any target runs
# (el7 on x86_64, el8 on aarch64), so it must be built on that distro.
#
# Usage: build-utils.sh <outdir>   (run from the repository root)
set -e

OUT=$1
[ -n "$OUT" ] || { echo "usage: $0 <outdir>" >&2; exit 1; }

. /etc/os-release
case "$VERSION_ID" in
7*)
    # CentOS 7 is EOL: its mirrors are gone, only the vault remains
    sed -i -e 's/^mirrorlist=/#mirrorlist=/' \
        -e 's|^#\?baseurl=http://mirror.centos.org|baseurl=https://vault.centos.org|' \
        /etc/yum.repos.d/CentOS-*.repo
    yum -y install gcc make binutils libcurl-devel fuse-devel
    ;;
8*)
    dnf -y --setopt=install_weak_deps=False install dnf-plugins-core
    dnf config-manager --set-enabled powertools
    dnf -y --setopt=install_weak_deps=False install gcc make binutils libcurl-devel fuse-devel libxcrypt-devel
    ;;
*)
    dnf -y --setopt=install_weak_deps=False install dnf-plugins-core
    dnf config-manager --set-enabled crb
    dnf -y --setopt=install_weak_deps=False install gcc make binutils libcurl-devel fuse-devel libxcrypt-devel
    ;;
esac

make -C confluent_osdeploy/utils
mkdir -p "$OUT"
cd confluent_osdeploy/utils
cp confluent_imginfo copernicus clortho autocons start_root urlmount "$OUT"/
make clean
