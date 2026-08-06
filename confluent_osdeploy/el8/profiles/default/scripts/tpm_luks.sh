#!/bin/sh
cryptdisk=$(blkid -t TYPE="crypto_LUKS"|sed -e s/:.*//)
if [ -x /bin/systemd-cryptenroll ]; then
    PASSWORD=$(cat /etc/confluent/luks.key) systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs="" $cryptdisk
    sed -e 's/ discard/ tpm2-device=auto,discard/' -i /etc/crypttab
    dracut -f
else
    clevis luks bind -f -d $cryptdisk -k - tpm2 '{}' < /etc/confluent/luks.key
    #cryptsetup luksRemoveKey $cryptdisk < /etc/confluent/confluent.apikey
fi
chmod 000 /etc/confluent/luks.key
