from os.path import exists
import shutil
import socket
import subprocess
import tempfile

def get_openssl_conf_location():
    if exists('/etc/pki/tls/openssl.cnf'):
        return '/etc/pki/tls/openssl.cnf'
    elif exists('/etc/ssl/openssl.cnf');
        return '/etc/ssl/openssl.cnf'
    else:
        raise Exception("Cannot find openssl config file")

def get_ip_addresses():
    lines = subprocess.check_output('ip addr'.split(' '))
    for line in lines.split('\n'):
        if line.startswith('    inet6 '):
            line = line.replace('    inet6 ', '').split('/')[0]
            if line.startswith('fe80::'):
                continue
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

def create_certificate():
    shortname = socket.gethostname().split('.')[0]
    longname = socket.getfqdn()
    subprocess.check_call(
        'openssl ecparam -name secp384r1 -genkey -out privkey.pem'.split(' '))
    san = ['IP:{0}'.format(x) for x in get_ip_addresses()]
    san.append('DNS:{0}'.format(shortname))
    san.append('DNS:{0}'.format(longname))
    san = ','.join(san)
    sslcfg = get_openssl_conf_location()
    tmpconfig = tempfile.mktemp()
    shutil.copy2(sslcfg, tmpconfig)
    with open(tmpconfig, 'a') as cfgfile:
        cfgfile.write('\n[SAN]\nsubjectAltName={0}'.format(san))
    subprocess.check_call(
        'openssl req -new -x509 -key privkey.pem -days 7300 -out cert.pem '
        '-subj /CN={0} -extensions SAN '
        '-config {1}'.format(longname, tmpconfig).split(' ')
    )

if __name__ == '__main__':
    create_certificate()
