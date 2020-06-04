#!/bin/sh
cryptdisk=$(blkid -t TYPE="crypto_LUKS"|sed -e s/:.*//)
clevis luks bind -f -d $cryptdisk -k - tpm2 '{"pcr_bank": "sha256", "pcr_ids": "7"}' < /etc/confluent/confluent.apikey
cryptsetup luksRemoveKey $cryptdisk < /etc/confluent/confluent.apikey
