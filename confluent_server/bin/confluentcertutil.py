import os
import confluent.collective.manager as collective
from os.path import exists
import shutil
import socket
import eventlet.green.subprocess as subprocess
import tempfile

def get_openssl_conf_location():
    if exists('/etc/pki/tls/openssl.cnf'):
        return '/etc/pki/tls/openssl.cnf'
    elif exists('/etc/ssl/openssl.cnf'):
        return '/etc/ssl/openssl.cnf'
    else:
        raise Exception("Cannot find openssl config file")

def get_ip_addresses():
    lines = subprocess.check_output('ip addr'.split(' '))
    if not isinstance(lines, str):
        lines = lines.decode('utf8')
    for line in lines.split('\n'):
        if line.startswith('    inet6 '):
            line = line.replace('    inet6 ', '').split('/')[0]
            if line == '::1':
                continue
        elif line.startswith('    inet '):
            line = line.replace('    inet ', '').split('/')[0]
            if line == '127.0.0.1':
                continue
            if line.startswith('169.254.'):
                continue
        else:
            continue
        yield line

def create_certificate(outdir):
    keyout = os.path.join(outdir, 'key.pem')
    certout = os.path.join(outdir, 'cert.pem')
    shortname = socket.gethostname().split('.')[0]
    longname = socket.getfqdn()
    subprocess.check_call(
        ['openssl', 'ecparam', '-name', 'secp384r1', '-genkey', '-out',
         keyout])
    san = ['IP:{0}'.format(x) for x in get_ip_addresses()]
    # It is incorrect to put IP addresses as DNS type.  However
    # there exists non-compliant clients that fail with them as IP
    san.extend(['DNS:{0}'.format(x) for x in get_ip_addresses()])
    san.append('DNS:{0}'.format(shortname))
    san.append('DNS:{0}'.format(longname))
    san = ','.join(san)
    sslcfg = get_openssl_conf_location()
    tmpconfig = tempfile.mktemp()
    shutil.copy2(sslcfg, tmpconfig)
    try:
        with open(tmpconfig, 'a') as cfgfile:
            cfgfile.write('\n[SAN]i\nbasicConstraints = CA:true\nsubjectAltName={0}'.format(san))
        subprocess.check_call([
            'openssl', 'req', '-new', '-x509', '-key', keyout, '-days',
            '7300', '-out', certout, '-subj', '/CN={0}'.format(longname),
            '-extensions', 'SAN', '-config', tmpconfig
        ])
    finally:
        os.remove(tmpconfig)
    fname = '/var/lib/confluent/public/site/tls/{0}.cert'.format(
        collective.get_myname())
    shutil.copy2(certout, fname)
    hv = subprocess.check_output(
        ['openssl', 'x509', '-in', certout, '-hash', '-noout'])
    if not isinstance(hv, str):
        hv = hv.decode('utf8')
    hv = hv.strip()
    hashname = '/var/lib/confluent/public/site/tls/{0}.0'.format(hv)
    certname = '{0}.cert'.format(collective.get_myname())
    for currname in os.listdir('/var/lib/confluent/public/site/tls/'):
        currname = os.path.join('/var/lib/confluent/public/site/tls/', currname)
        if currname.endswith('.0'):
            try:
                realname = os.readlink(currname)
                if realname == certname:
                    os.unlink(currname)
            except OSError:
                pass
    os.symlink(certname, hashname)

if __name__ == '__main__':
    create_certificate(os.getcwd())
