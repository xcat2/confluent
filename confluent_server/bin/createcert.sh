#!/bin/bash
umask 0077
openssl ecparam -name secp384r1 -genkey -out /etc/confluent/privkey.pem
openssl req -new -x509 -key /etc/confluent/privkey.pem -days 760 -out /etc/confluent/srvcert.pem -subj /CN=$(hostname)
