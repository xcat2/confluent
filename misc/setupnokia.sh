#!/bin/bash

if [[ -z "$SWITCHUSER" || -z "$SWITCHPASS" ]]; then
    echo "Error: SWITCHUSER and SWITCHPASS environment variables must be set"
    exit 1
fi

if [[ $# -eq 0 ]]; then
    echo "Error: At least one argument is required"
    exit 1
fi

SWITCHNAME="$1"

# Create temporary SSH ASKPASS script
ASKPASS_SCRIPT=$(mktemp)
trap "rm -f $ASKPASS_SCRIPT" EXIT

cat > "$ASKPASS_SCRIPT" << 'EOF'
#!/bin/bash
echo "$SWITCHPASS"
EOF

chmod 700 "$ASKPASS_SCRIPT"

# Set SSH_ASKPASS environment variable
export SSH_ASKPASS="$ASKPASS_SCRIPT"
export SSH_ASKPASS_REQUIRE=force
export DISPLAY=none

CERTDIR=$(mktemp -d)
trap "rm -rf $CERTDIR" EXIT
cd "$CERTDIR"
python3 /opt/confluent/lib/python/confluent/certutil.py -s "$SWITCHNAME"
setsid ssh $SWITCHUSER@"$SWITCHNAME" <<EOC
enter candidate exclusive
/ system json-rpc-server admin-state enable
/ system tls profile fullcert key "$(<$CERTDIR/key.pem)"
/ system tls profile fullcert certificate "$(<$CERTDIR/cert.pem)"
/ system tls profile fullcert cipher-list [ ecdhe-ecdsa-aes256-gcm-sha384 ]
/ system json-rpc-server network-instance mgmt https admin-state enable
/ system json-rpc-server network-instance mgmt https tls-profile fullcert
commit save
EOC
