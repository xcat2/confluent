cat /tls/*.0 >> /etc/pki/tls/certs/ca-bundle.crt
if ! grep console= /proc/cmdline >& /dev/null; then
    autocons=$(/opt/confluent/bin/autocons)
    if [ -n "$autocons" ]; then
        echo console=$autocons |sed -e 's!/dev/!!' >> /tmp/01-autocons.conf
        autocons=${autocons%,*}
	echo $autocons > /tmp/01-autocons.devnode
	echo "Detected firmware specified console at $(cat /tmp/01-autocons.conf)" > $autocons
    fi
fi
