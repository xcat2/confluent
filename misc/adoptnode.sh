#!/bin/bash
TARGNODE=$1
TARGPROF=$2
if [ -z "$TARGNODE" ] ; then
	echo "Target node must be specified"
	exit 1
fi
if [ -z "$TARGPROF" ]; then
	echo "Target profile must be specified"
	exit 1
fi
nodedefine $TARGNODE deployment.apiarmed=once deployment.profile=$TARGPROF deployment.useinsecureprotocols= deployment.pendingprofile=$TARGPROF
cat /var/lib/confluent/public/site/ssh/*pubkey | ssh $TARGNODE "mkdir -p /root/.ssh/; cat - >> /root/.ssh/authorized_keys"
ssh $TARGNODE mkdir -p /etc/confluent /opt/confluent/bin
cat /var/lib/confluent/public/site/tls/*.pem | ssh $TARGNODE "cat - >> /etc/confluent/ca.pem"
cat /var/lib/confluent/public/site/tls/*.pem | ssh $TARGNODE "cat - >> /etc/pki/ca-trust/source/anchors/confluent.pem"
nodeattrib $TARGNODE id.uuid=$(ssh $TARGNODE cat /sys/devices/virtual/dmi/id/product_uuid)
scp prepadopt.sh $TARGNODE:/tmp/
scp finalizeadopt.sh $TARGNODE:/tmp/
ssh $TARGNODE bash /tmp/prepadopt.sh $TARGNODE $TARGPROF
nodeattrib $TARGNODE deployment.pendingprofile=
nodeapply $TARGNODE -k
ssh $TARGNODE sh /tmp/finalizeadopt.sh
