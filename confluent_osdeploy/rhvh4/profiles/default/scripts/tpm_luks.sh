#!/bin/sh
cryptdisk=$(blkid -t TYPE="crypto_LUKS"|sed -e s/:.*//)
clevis luks bind -f -d $cryptdisk -k - tpm2 '{}' < /etc/confluent/confluent.apikey
cryptsetup luksRemoveKey $cryptdisk < /etc/confluent/confluent.apikey
