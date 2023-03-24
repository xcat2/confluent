import argparse
import io
import gzip
import pyghmi.redfish.command as cmd
import os
import sys

ap = argparse.ArgumentParser(description='Certificate Generate')
ap.add_argument('xcc', help='XCC address')
ap.add_argument('--country', help='Two Letter Country')
ap.add_argument('--state', help='State or Province')
ap.add_argument('--city', help='City or Locality')
ap.add_argument('--org', help='Organization name')
ap.add_argument('--name', help='Common/Host Name')
args = ap.parse_args()

c = cmd.Command(args.xcc, os.environ['XCCUSER'], os.environ['XCCPASS'],
                verifycallback=lambda x: True)
params = [
        '0', # 'serviceType'
        args.country,
        args.state,
        args.city,
        args.org,
        args.name,
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        '0', # ECDSA cert, 1, 2048 for RSA
        '256',
]
wc = c.oem.wc
rsp, status = wc.grab_json_response_with_status('/api/function', {'Sec_GenKeyAndCSR': ','.join(params)})
rsp, status = wc.grab_json_response_with_status('/api/dataset', {'CSR_Format': '1'})
rsp, status = wc.grab_json_response_with_status('/api/function', {'Sec_DownloadCSRANDCert': '0,4,0'})
wc.request('GET', '/download/{0}'.format(rsp['FileName']))
rsp = wc.getresponse()
csr = rsp.read()
if rsp.getheader('Content-Encoding', None) == 'gzip':
    csr = gzip.GzipFile(fileobj=io.BytesIO(csr)).read()
print(csr.decode('utf8'))
        
