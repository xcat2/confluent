#!/bin/bash
if [ -z "$MOKPASS" ]; then
	echo "MOKPASS must be set to proceed"
	exit 1
fi
set -euo pipefail
node=$2
file=$1
nodersync $file $node:/tmp/
ssh $node mokutil --delete /tmp/$file --root-pw
ssh $node reboot
nodeconsole $node -ea deletemok.nca
