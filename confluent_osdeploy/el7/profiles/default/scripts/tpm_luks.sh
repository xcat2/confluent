#!/bin/sh
cryptdisk=$(blkid -t TYPE="crypto_LUKS"|sed -e s/:.*//)

pcrs=""
if [ -f /tmp/cryptboot ]; then
    # syntax of /tmp/cryptboot is e.g. tpm2:pcrs=1,7
    pcrs=$(sed -e 's/^tpm2:pcrs=//' /tmp/cryptboot)
fi

if [ -n "$pcrs" ]; then
    clevispcrs=$(echo "$pcrs" | sed -e 's/,/, /g')
    clevis luks bind -f -d $cryptdisk -k - tpm2 "{\"pcr_ids\":\"$clevispcrs\"}" < /etc/confluent/confluent.apikey
else
    clevis luks bind -f -d $cryptdisk -k - tpm2 '{}' < /etc/confluent/confluent.apikey
fi
cryptsetup luksRemoveKey $cryptdisk < /etc/confluent/confluent.apikey
