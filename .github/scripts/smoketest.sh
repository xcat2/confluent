#!/bin/bash
# Install the freshly built rpms on a clean EL9/EL10 system with EPEL enabled
# and verify the server actually imports and starts.
#
# Usage: smoketest.sh <dir-with-rpms>
set -x

RPMDIR=$(readlink -f "$1")
FAIL=0

dnf -y install epel-release
dnf config-manager --set-enabled crb || true

echo "::group::install client, vtbufferd, imgutil via dnf"
dnf -y install "$RPMDIR"/*/confluent_client-*.noarch.rpm \
               "$RPMDIR"/*/confluent_vtbufferd-*.rpm \
               "$RPMDIR"/*/confluent_imgutil-*.noarch.rpm || FAIL=1
echo "::endgroup::"

echo "::group::install server (dnf, fall back to --nodeps for known-missing deps)"
SERVERRPM=$(ls "$RPMDIR"/*/confluent_server-*.noarch.rpm | head -1)
if ! dnf -y install "$SERVERRPM"; then
    # expected: python3-webauthn (and python3-eficompressor on el9) are not in EPEL
    rpm -qpR "$SERVERRPM" | grep -vE '^(confluent|rpmlib|/)' | sed 's/ [<>=].*//' | sort -u > /tmp/reqs
    xargs -a /tmp/reqs dnf -y install --skip-broken
    rpm -ivh --nodeps "$SERVERRPM" || FAIL=1
fi
echo "::endgroup::"

echo "::group::install osdeploy (--nodeps: requires Lenovo confluent_ipxe)"
rpm -ivh --nodeps "$RPMDIR"/*/confluent_osdeploy-x86_64-*.noarch.rpm || FAIL=1
test -d /opt/confluent/lib/osdeploy/el10/profiles || FAIL=1
echo "::endgroup::"

echo "::group::import and daemon smoke test"
export PYTHONPATH=/opt/confluent/lib/python
python3 -c "import confluent.main; print('IMPORT confluent.main: OK')" || FAIL=1
python3 -c "import confluent.snmputil; print('IMPORT confluent.snmputil: OK')" || FAIL=1
python3 -c "import aiohmi.redfish.command; print('IMPORT aiohmi.redfish: OK')" || FAIL=1
timeout 15 /opt/confluent/bin/confluent 2>&1 | head -5
sleep 8
if pgrep -f confluent > /dev/null; then
    echo "DAEMON_RUNNING=yes"
else
    echo "DAEMON_RUNNING=no"
    FAIL=1
fi
echo "::endgroup::"

exit $FAIL
