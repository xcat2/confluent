#!/bin/sh
cryptdisk=$(blkid -t TYPE="crypto_LUKS"|sed -e s/:.*//)

pcrs=$(sed -n -e 's/.*tpm2:pcrs=\([0-9,]*\).*/\1/p' /tmp/cryptboot)

if [ -x /bin/systemd-cryptenroll ]; then
    PASSWORD=$(cat /etc/confluent/luks.key) systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs="$pcrs" $cryptdisk
    sed -e 's/ discard/ tpm2-device=auto,discard/' -i /etc/crypttab
    dracut -f
else
    if [ -n "$pcrs" ]; then
        clevispcrs=$(echo "$pcrs" | sed -e 's/,/, /g')
        clevis luks bind -f -d $cryptdisk -k - tpm2 "{\"pcr_ids\":\"$clevispcrs\"}" < /etc/confluent/luks.key
    else
        clevis luks bind -f -d $cryptdisk -k - tpm2 "{}" < /etc/confluent/luks.key
    fi
    #cryptsetup luksRemoveKey $cryptdisk < /etc/confluent/confluent.apikey
fi
chmod 000 /etc/confluent/luks.key
