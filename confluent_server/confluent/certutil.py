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

def check_apache_config(path):
    keypath = None
    certpath = None
    with open(path, 'r') as openf:
        webconf = openf.read()
    for line in webconf.split('\n'):
        line = line.strip()
        line = line.split('#')[0]
        if line.startswith('SSLCertificateFile'):
            _, certpath = line.split(None, 1)
        if line.startswith('SSLCertificateKeyFile'):
            _, keypath = line.split(None, 1)
    return keypath, certpath

def get_certificate_paths():
    keypath = None
    certpath = None
    if os.path.exists('/etc/httpd/conf.d/ssl.conf'): # redhat way
        keypath, certpath = check_apache_config('/etc/httpd/conf.d/ssl.conf')
    if not keypath and os.path.exists('/etc/apache2'): # suse way
        for currpath, _, files in os.walk('/etc/apache2'):
            for fname in files:
                if fname.endswith('.template'):
                    continue
                kploc = check_apache_config(os.path.join(currpath,
                                                                       fname))
                if keypath and kploc[0]:
                    return None, None # Ambiguous...
                if kploc[0]:
                    keypath, certpath = kploc

    return keypath, certpath

def assure_tls_ca():
    keyout, certout = ('/etc/confluent/tls/cakey.pem', '/etc/confluent/tls/cacert.pem')
    if os.path.exists(certout):
        return
    try:
        os.makedirs('/etc/confluent/tls')
    except OSError as e:
        if e.errno != 17:
            raise
    sslcfg = get_openssl_conf_location()
    tmpconfig = tempfile.mktemp()
    shutil.copy2(sslcfg, tmpconfig)
    subprocess.check_call(
        ['openssl', 'ecparam', '-name', 'secp384r1', '-genkey', '-out',
         keyout])
    try:
        with open(tmpconfig, 'a') as cfgfile:
            cfgfile.write('\n[CACert]\nbasicConstraints = CA:true\n')
        subprocess.check_call([
            'openssl', 'req', '-new', '-x509', '-key', keyout, '-days',
            '27300', '-out', certout, '-subj',
            '/CN=Confluent TLS Certificate authority ({0})'.format(socket.gethostname()),
            '-extensions', 'CACert', '-config', tmpconfig
        ])
    finally:
        os.remove(tmpconfig)
    # Could restart the webserver now?
    fname = '/var/lib/confluent/public/site/tls/{0}.pem'.format(
        collective.get_myname())
    try:
        os.makedirs(os.path.dirname(fname))
    except OSError as e:
        if e.errno != 17:
            raise
    shutil.copy2('/etc/confluent/tls/cacert.pem', fname)
    hv = subprocess.check_output(
        ['openssl', 'x509', '-in', '/etc/confluent/tls/cacert.pem', '-hash', '-noout'])
    if not isinstance(hv, str):
        hv = hv.decode('utf8')
    hv = hv.strip()
    hashname = '/var/lib/confluent/public/site/tls/{0}.0'.format(hv)
    certname = '{0}.pem'.format(collective.get_myname())
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

def create_certificate(keyout=None, certout=None):
    if not keyout:
        keyout, certout = get_certificate_paths()
    if not keyout:
        raise Exception('Unable to locate TLS certificate path automatically')
    assure_tls_ca()
    shortname = socket.gethostname().split('.')[0]
    longname = shortname # socket.getfqdn()
    subprocess.check_call(
        ['openssl', 'ecparam', '-name', 'secp384r1', '-genkey', '-out',
         keyout])
    san = ['IP:{0}'.format(x) for x in get_ip_addresses()]
    # It is incorrect to put IP addresses as DNS type.  However
    # there exists non-compliant clients that fail with them as IP
    san.extend(['DNS:{0}'.format(x) for x in get_ip_addresses()])
    san.append('DNS:{0}'.format(shortname))
    #san.append('DNS:{0}'.format(longname))
    san = ','.join(san)
    sslcfg = get_openssl_conf_location()
    tmpconfig = tempfile.mktemp()
    extconfig = tempfile.mktemp()
    csrout = tempfile.mktemp()
    shutil.copy2(sslcfg, tmpconfig)
    try:
        with open(tmpconfig, 'a') as cfgfile:
            cfgfile.write('\n[SAN]\nsubjectAltName={0}'.format(san))
        with open(extconfig, 'a') as cfgfile:
            cfgfile.write('\nbasicConstraints=CA:false\nsubjectAltName={0}'.format(san))
        subprocess.check_call([
            'openssl', 'req', '-new', '-key', keyout, '-out', csrout, '-subj',
            '/CN={0}'.format(longname),
            '-extensions', 'SAN', '-config', tmpconfig
        ])
        subprocess.check_call([
            'openssl', 'x509', '-req', '-in', csrout,
            '-CA', '/etc/confluent/tls/cacert.pem',
            '-CAkey', '/etc/confluent/tls/cakey.pem',
            '-set_serial', '0x123', '-out', certout, '-days', '27300',
            '-extfile', extconfig
        ])
    finally:
        os.remove(tmpconfig)
        os.remove(csrout)
        os.remove(extconfig)


if __name__ == '__main__':
    outdir = os.getcwd()
    keyout = os.path.join(outdir, 'key.pem')
    certout = os.path.join(outdir, 'cert.pem')
    create_certificate(keyout, certout)
