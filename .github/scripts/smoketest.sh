#!/bin/bash
# Install a nightly bundle on a clean EL, openSUSE or Ubuntu container and
# check that the server imports and starts.
#
# Every dependency has to resolve from the distribution's own repositories
# (plus EPEL on EL), so a missing one fails the run.
#
# Usage: smoketest.sh <dir with the packages to install>
set -x

PKGDIR=$(readlink -f "$1")
FAIL=0
. /etc/os-release

case "$ID" in
almalinux|rocky|rhel|centos)
    dnf -y install epel-release
    dnf config-manager --set-enabled crb
    dnf -y install procps-ng util-linux
    echo "::group::install packages"
    dnf -y install "$PKGDIR"/*.rpm || FAIL=1
    echo "::endgroup::"
    ;;
opensuse-leap|sles)
    zypper -n install procps util-linux
    echo "::group::install packages"
    # nightly rpms are unsigned
    zypper -n --no-gpg-checks install --allow-unsigned-rpm "$PKGDIR"/*.rpm || FAIL=1
    echo "::endgroup::"
    ;;
ubuntu|debian)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get -y install procps util-linux
    echo "::group::install packages"
    apt-get -y install "$PKGDIR"/*.deb || FAIL=1
    echo "::endgroup::"
    ;;
*)
    echo "unsupported distribution $ID" >&2
    exit 1
    ;;
esac

echo "::group::installed content"
test -d /opt/confluent/lib/osdeploy/el10/profiles || FAIL=1
test -f /opt/confluent/lib/ipxe/ipxe.efi || FAIL=1
test -x /opt/confluent/bin/browserfs || FAIL=1
test -x /opt/confluent/bin/vinz || FAIL=1
test -x /opt/confluent/bin/vtbufferd || FAIL=1
test -x /opt/confluent/bin/imgutil || FAIL=1
echo "::endgroup::"

echo "::group::import and daemon smoke test"
export PYTHONPATH=/opt/confluent/lib/python
python3 -c "import confluent.main; print('IMPORT confluent.main: OK')" || FAIL=1
python3 -c "import confluent.snmputil; print('IMPORT confluent.snmputil: OK')" || FAIL=1
python3 -c "import aiohmi.redfish.command; print('IMPORT aiohmi.redfish: OK')" || FAIL=1
# packaging sets up non-root operation (/etc/confluent owned by confluent),
# and there is no systemd in the container to start it, so run it directly
mkdir -p /var/run/confluent
chown confluent:confluent /var/run/confluent
timeout 60 runuser -u confluent -- /opt/confluent/bin/confluent -f > /tmp/confluentd.log 2>&1 &
for _ in $(seq 30); do
    [ -S /var/run/confluent/api.sock ] && break
    sleep 1
done
if [ -S /var/run/confluent/api.sock ] && /opt/confluent/bin/confetty show /; then
    echo "DAEMON_RUNNING=yes"
else
    echo "DAEMON_RUNNING=no"
    FAIL=1
fi
cat /tmp/confluentd.log
pkill -f /opt/confluent/bin/confluent
echo "::endgroup::"

exit $FAIL
