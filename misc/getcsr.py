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
ap.add_argument('outcsr', help='CSR filename to save')
args = ap.parse_args()

c = cmd.Command(args.xcc, os.environ['XCCUSER'], os.environ['XCCPASS'],
                verifycallback=lambda x: True)

overview = c._do_web_request('/redfish/v1/')
cs = overview.get('CertificateService', {}).get('@odata.id', None)
if cs:
    csinfo = c._do_web_request(cs)
    gcsr = csinfo.get('Actions', {}).get('#CertificateService.GenerateCSR', {}).get('target', None)
    if gcsr:
        #https://n241-bmc/redfish/v1/Managers/1/NetworkProtocol HTTPS
        #/redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates
        #/redfish/v1/CertificateService/CertificateLocations
        csrargs = {
                'City': args.city,
                'State': args.state,
                'Organization': args.org,
                'Country': args.country,
                'CommonName': args.name,
                'KeyPairAlgorithm': 'TPM_ALG_ECDH',
                'KeyCurveId': 'TPM_ECC_NIST_P384',
                'CertificateCollection': { '@odata.id': '/redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates'}
        }

        csrinfo = c._do_web_request(gcsr, csrargs)
        if 'CSRString' in csrinfo:
            with open(args.outcsr, 'w') as csrout:
                csrout.write(csrinfo['CSRString'])
            sys.exit(0)

else:
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
    print(csr)
        
