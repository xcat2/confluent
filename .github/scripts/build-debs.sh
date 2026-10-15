#!/bin/bash
# Build the confluent debs in an Ubuntu container, like build/arm/*/buildapt.sh:
# every component with a builddeb script, plus alien conversions of the rpms
# that have no deb packaging of their own (osdeploy, ipxe, browserfs, vinz).
# With --arch-only, only the architecture-specific ones: confluent_vtbufferd
# and the conversions of rpms that are not noarch.
#
# Usage: build-debs.sh [--arch-only] <outdir> [<dir with rpms to convert>]
set -e

ARCHONLY=
if [ "$1" = "--arch-only" ]; then
    ARCHONLY=1
    shift
fi
OUT=$(readlink -f "$1")
RPMS=${2:+$(readlink -f "$2")}
[ -n "$OUT" ] || { echo "usage: $0 [--arch-only] <outdir> [rpmdir]" >&2; exit 1; }

cd "$(dirname "$0")/../.."
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -y --no-install-recommends install git build-essential debhelper devscripts dh-python fakeroot \
    python3-all python3-setuptools python3-stdeb pandoc patch alien
# stdeb on noble still imports the SafeConfigParser python 3.12 removed
if (cd / && patch -p1 --dry-run -s < "$OLDPWD/build/arm/noble/stdeb.patch") > /dev/null 2>&1; then
    (cd / && patch -p1 < "$OLDPWD/build/arm/noble/stdeb.patch")
fi
git config --global --add safe.directory '*'
./mkversion

mkdir -p "$OUT"
# vtbufferd first: it recreates /tmp/confluent, which client and server reuse
./confluent_vtbufferd/builddeb "$OUT"
if [ -z "$ARCHONLY" ]; then
    ./confluent_client/builddeb "$OUT"
    ./confluent_server/builddeb "$OUT"
    ./imgutil/builddeb "$OUT"
fi

if [ -n "$RPMS" ]; then
    skip=(! -name '*.src.rpm')
    [ -n "$ARCHONLY" ] && skip+=(! -name '*.noarch.rpm')
    cd "$OUT"
    find "$RPMS" -name '*.rpm' "${skip[@]}" -print0 |
        xargs -0 -r -n1 fakeroot alien --to-deb --scripts --keep-version
fi
ls -la "$OUT"
