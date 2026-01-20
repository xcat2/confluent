#!/bin/bash
TARGNODE=$1
TARGPROF=$2
TARGIDENT=$3
TMPDIR=$(mktemp -d)
cd $TMPDIR
DEPLOYSRV=$(echo $SSH_CLIENT|awk '{print $1}')
UDEPLOYSRV=$DEPLOYSRV
if [[ "$DEPLOYSRV" = *":"* ]]; then
	UDEPLOYSRV="[$DEPLOYSRV]"
fi
update-ca-trust
mkdir -p /etc/confluent
curl -sg https://$UDEPLOYSRV/confluent-public/os/$TARGPROF/boot/initramfs/addons.cpio > addons.cpio
curl -sg https://$UDEPLOYSRV/confluent-public/os/$TARGPROF/scripts/functions > /etc/confluent/functions
cpio -dumi < addons.cpio
systemctl status firewalld >& /dev/null && FWACTIVE=1
if [ "$FWACTIVE" == 1 ]; then systemctl stop firewalld; fi
opt/confluent/bin/copernicus  > /etc/confluent/confluent.info
#opt/confluent/bin/clortho $TARGNODE $DEPLOYSRV > /etc/confluent/confluent.apikey
. /etc/confluent/functions
confluentpython opt/confluent/bin/apiclient -i $TAGRIDENT /confluent-api/self/deploycfg2 > /etc/confluent/confluent.deploycfg
if [ "$FWACTIVE" == 1 ]; then systemctl start firewalld; fi
cp opt/confluent/bin/apiclient /opt/confluent/bin
#curl -sg -H "CONFLUENT_APIKEY: $(cat /etc/confluent/confluent.apikey)" -H "CONFLUENT_NODENAME: $TARGNODE" https://$UDEPLOYSRV/confluent-api/self/deploycfg2 > /etc/confluent/confluent.deploycfg
# python3 /opt/confluent/bin/apiclient /confluent-api/self/deploycfg2 > /etc/confluent/confluent.deploycfg
cd -
echo rm -rf $TMPDIR
