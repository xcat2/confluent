#!/bin/sh
rootpassword=$(grep ^rootpassword: /etc/confluent/confluent.deploycfg)
rootpassword=${rootpassword#rootpassword: }
if [ "$rootpassword" = "null" ]; then
    rootpassword=""
fi

if [ ! -z "$rootpassword" ]; then
    sed -i "s@root:[^:]*:@root:$rootpassword:@" /sysroot/etc/shadow
fi
