#!/bin/bash
echo -n "" >> /tmp/net.ifaces
echo -n "" > /tmp/01-autocons.devnode
BUNDLENAME=/etc/pki/tls/certs/ca-bundle.crt
if [ ! -e "$BUNDLENAME" ]; then
    BUNDLENAME=/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
    mkdir -p /etc/pki/tls/certs
    ln -s $BUNDLENAME /etc/pki/tls/certs/ca-bundle.crt
fi
cat /tls/*.0 >> $BUNDLENAME
if ! grep console= /proc/cmdline >& /dev/null; then
    autocons=$(/opt/confluent/bin/autocons)
    if [ -n "$autocons" ]; then
        echo console=$autocons |sed -e 's!/dev/!!' >> /tmp/01-autocons.conf
        autocons=${autocons%,*}
        echo $autocons > /tmp/01-autocons.devnode
        echo "Detected firmware specified console at $(cat /tmp/01-autocons.conf)" > $autocons
        echo "Initializing auto detected console when installer starts" > $autocons
    fi
fi
if grep console=ttyS /proc/cmdline >& /dev/null; then
    echo "Serial console has been requested in the kernel arguments, the local video may not show progress" > /dev/tty1
fi
. /lib/anaconda-lib.sh
echo rd.fcoe=0 > /etc/cmdline.d/nofcoe.conf
wait_for_kickstart
