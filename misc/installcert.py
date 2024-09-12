import argparse
import pyghmi.redfish.command as cmd
import os
import sys

ap = argparse.ArgumentParser(description='Certificate Generate')
ap.add_argument('xcc', help='XCC address')
ap.add_argument('cert', help='Certificate in PEM format')
args = ap.parse_args()

cert = open(args.cert, 'r').read()
c = cmd.Command(args.xcc, os.environ['XCCUSER'], os.environ['XCCPASS'],
                verifycallback=lambda x: True)
overview = c._do_web_request('/redfish/v1/')
cs = overview.get('CertificateService', {}).get('@odata.id', None)
if cs:
    csinfo = c._do_web_request(cs)
    gcsr = csinfo.get('Actions', {}).get('#CertificateService.ReplaceCertificate', {}).get('target', None)
    if gcsr:
        repcertargs = {
                'CertificateUri': { '@odata.id': '/redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates/1' },
                'CertificateType': 'PEM',
                'CertificateString': cert }
        print(repr(c._do_web_request(gcsr, repcertargs)))
        sys.exit(0)

    #CertificateService.ReplaceCertificate
wc = c.oem.wc
cert = open(args.cert, 'rb').read()
res = wc.grab_json_response_with_status('/api/function', {'Sec_ImportCert': '0,1,0,0,,{0}'.format(cert)})
print(repr(res))
