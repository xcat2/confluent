import argparse
import pyghmi.redfish.command as cmd
import os
import sys

ap = argparse.ArgumentParser(description='Certificate Generate')
ap.add_argument('xcc', help='XCC address')
ap.add_argument('cert', help='Certificate in PEM format')
args = ap.parse_args()

c = cmd.Command(args.xcc, os.environ['XCCUSER'], os.environ['XCCPASS'],
                verifycallback=lambda x: True)
wc = c.oem.wc
rawcert = open(args.cert, 'r').read()
cert = ''
incert = False
for line in rawcert.split('\n'):
    if incert or '-----BEGIN CERTIFICATE-----' in line:
        incert = True
        cert += line + '\n'
res = wc.grab_json_response_with_status('/api/function', {'Sec_ImportCert': '0,1,0,0,,{0}'.format(cert)})
print(repr(res))
