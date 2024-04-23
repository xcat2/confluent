import os
import confluent.collective.manager as collective
import confluent.util as util
from os.path import exists
import shutil
import socket
import eventlet.green.subprocess as subprocess
import tempfile

def mkdirp(targ):
    try:
        return os.makedirs(targ)
    except OSError as e:
        if e.errno != 17:
            raise

def get_openssl_conf_location():
    if exists('/etc/pki/tls/openssl.cnf'):
        return '/etc/pki/tls/openssl.cnf'
    elif exists('/etc/ssl/openssl.cnf'):
        return '/etc/ssl/openssl.cnf'
    else:
        raise Exception("Cannot find openssl config file")

def normalize_uid():
    curruid = os.geteuid()
    neededuid = os.stat('/etc/confluent').st_uid
    if curruid != neededuid:
        os.seteuid(neededuid)
    if os.geteuid() != neededuid:
        raise Exception('Need to run as root or owner of /etc/confluent')
    return curruid

def get_ip_addresses():
    lines, _ = util.run(['ip', 'addr'])
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
    if not os.path.exists(certout):
        #create_simple_ca(keyout, certout)
        create_full_ca(certout)
    fname = '/var/lib/confluent/public/site/tls/{0}.pem'.format(
        collective.get_myname())
    ouid = normalize_uid()
    try:
        os.makedirs(os.path.dirname(fname))
    except OSError as e:
        if e.errno != 17:
            os.seteuid(ouid)
            raise
    try:
        shutil.copy2('/etc/confluent/tls/cacert.pem', fname)
        hv, _ = util.run(
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
    finally:
        os.seteuid(ouid)

def substitute_cfg(setting, key, val, newval, cfgfile, line):
    if key.strip() == setting:
        cfgfile.write(line.replace(val, newval) + '\n')
        return True
    return False

def create_full_ca(certout):
    mkdirp('/etc/confluent/tls/ca/private')
    keyout = '/etc/confluent/tls/ca/private/cakey.pem'
    csrout = '/etc/confluent/tls/ca/ca.csr'
    mkdirp('/etc/confluent/tls/ca/newcerts')
    with open('/etc/confluent/tls/ca/index.txt', 'w') as idx:
        pass
    with open('/etc/confluent/tls/ca/index.txt.attr', 'w') as idx:
        idx.write('unique_subject = no')
    with open('/etc/confluent/tls/ca/serial', 'w') as srl:
        srl.write('01')
    sslcfg = get_openssl_conf_location()
    newcfg = '/etc/confluent/tls/ca/openssl.cfg'
    settings = {
        'dir': '/etc/confluent/tls/ca',
        'certificate': '$dir/cacert.pem',
        'private_key': '$dir/private/cakey.pem',
        'countryName': 'optional',
        'stateOrProvinceName': 'optional',
        'organizationName': 'optional',
    }
    subj = '/CN=Confluent TLS Certificate authority ({0})'.format(socket.gethostname())
    if len(subj) > 68:
        subj = subj[:68]
    with open(sslcfg, 'r') as cfgin:
        with open(newcfg, 'w') as cfgfile:
            for line in cfgin.readlines():
                cfg = line.split('#')[0]
                if '=' in cfg:
                    key, val = cfg.split('=', 1)
                    for stg in settings:
                        if substitute_cfg(stg, key, val, settings[stg], cfgfile, line):
                            break
                    else:
                        cfgfile.write(line.strip() + '\n')
                    continue
                cfgfile.write(line.strip() + '\n')
            cfgfile.write('\n[CACert]\nbasicConstraints = CA:true\n\n[ca_confluent]\n')
    subprocess.check_call(
        ['openssl', 'ecparam', '-name', 'secp384r1', '-genkey', '-out',
        keyout])
    subprocess.check_call(
        ['openssl', 'req', '-new', '-key', keyout, '-out', csrout, '-subj', subj])
    subprocess.check_call(
        ['openssl', 'ca', '-config', newcfg, '-batch', '-selfsign',
        '-extensions', 'CACert', '-extfile', newcfg, 
        '-notext', '-startdate',
         '19700101010101Z', '-enddate', '21000101010101Z', '-keyfile',
         keyout, '-out', '/etc/confluent/tls/ca/cacert.pem', '-in', csrout]
    )
    shutil.copy2('/etc/confluent/tls/ca/cacert.pem', certout)
#openssl ca -config openssl.cnf -selfsign -keyfile cakey.pem -startdate 20150214120000Z -enddate 20160214120000Z
#20160107071311Z -enddate 20170106071311Z

def create_simple_ca(keyout, certout):
    try:
        os.makedirs('/etc/confluent/tls')
    except OSError as e:
        if e.errno != 17:
            raise
    sslcfg = get_openssl_conf_location()
    tmphdl, tmpconfig = tempfile.mkstemp()
    os.close(tmphdl)
    shutil.copy2(sslcfg, tmpconfig)
    subprocess.check_call(
            ['openssl', 'ecparam', '-name', 'secp384r1', '-genkey', '-out',
            keyout])
    try:
        subj = '/CN=Confluent TLS Certificate authority ({0})'.format(socket.gethostname())
        if len(subj) > 68:
            subj = subj[:68]
        with open(tmpconfig, 'a') as cfgfile:
            cfgfile.write('\n[CACert]\nbasicConstraints = CA:true\n')
        subprocess.check_call([
                'openssl', 'req', '-new', '-x509', '-key', keyout, '-days',
                '27300', '-out', certout, '-subj', subj,
                '-extensions', 'CACert', '-config', tmpconfig
            ])
    finally:
        os.remove(tmpconfig)

def create_certificate(keyout=None, certout=None, csrout=None):
    if not keyout:
        keyout, certout = get_certificate_paths()
    if not keyout:
        raise Exception('Unable to locate TLS certificate path automatically')
    assure_tls_ca()
    shortname = socket.gethostname().split('.')[0]
    longname = shortname # socket.getfqdn()
    if not csrout:
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
    tmphdl, tmpconfig = tempfile.mkstemp()
    os.close(tmphdl)
    tmphdl, extconfig = tempfile.mkstemp()
    os.close(tmphdl)
    needcsr = False
    if csrout is None:
        needcsr = True
        tmphdl, csrout = tempfile.mkstemp()
        os.close(tmphdl)
    shutil.copy2(sslcfg, tmpconfig)
    try:
        if needcsr:
            with open(tmpconfig, 'a') as cfgfile:
                cfgfile.write('\n[SAN]\nsubjectAltName={0}'.format(san))
            with open(extconfig, 'a') as cfgfile:
                cfgfile.write('\nbasicConstraints=CA:false\nsubjectAltName={0}'.format(san))
            subprocess.check_call([
                'openssl', 'req', '-new', '-key', keyout, '-out', csrout, '-subj',
                '/CN={0}'.format(longname),
               '-extensions', 'SAN', '-config', tmpconfig
            ])
        else:
            # when used manually, allow the csr SAN to stand
            # may add explicit subj/SAN argument, in which case we would skip copy
            with open(tmpconfig, 'a') as cfgfile:
                cfgfile.write('\ncopy_extensions=copy\n')
            with open(extconfig, 'a') as cfgfile:
                cfgfile.write('\nbasicConstraints=CA:false\n')
        if os.path.exists('/etc/confluent/tls/cakey.pem'):
            # simple style CA in effect, make a random serial number and
            # hope for the best, and accept inability to backdate the cert
            serialnum = '0x' + ''.join(['{:02x}'.format(x) for x in bytearray(os.urandom(20))])
            subprocess.check_call([
                'openssl', 'x509', '-req', '-in', csrout,
                '-CA', '/etc/confluent/tls/cacert.pem',
                '-CAkey', '/etc/confluent/tls/cakey.pem',
                '-set_serial', serialnum, '-out', certout, '-days', '27300',
                '-extfile', extconfig
            ])
        else:
            # we moved to a 'proper' CA, mainly for access to backdating
            # start of certs for finicky system clocks
            # this also provides a harder guarantee of serial uniqueness, but
            # not of practical consequence (160 bit random value is as good as
            # guaranteed unique)
            # downside is certificate generation is serialized
            cacfgfile = '/etc/confluent/tls/ca/openssl.cfg'
            if needcsr:
                tmphdl, tmpcafile = tempfile.mkstemp()
                shutil.copy2(cacfgfile, tmpcafile)
                os.close(tmphdl)
                cacfgfile = tmpcafile
            # with realcalock:  # if we put it in server, we must lock it
            subprocess.check_call([
                'openssl', 'ca', '-config', cacfgfile,
                '-in', csrout, '-out', certout, '-batch', '-notext',
                '-startdate', '19700101010101Z', '-enddate', '21000101010101Z',
                '-extfile', extconfig
            ])
    finally:
        os.remove(tmpconfig)
        if needcsr:
            os.remove(csrout)
        print(extconfig)  # os.remove(extconfig)


if __name__ == '__main__':
    import sys
    outdir = os.getcwd()
    keyout = os.path.join(outdir, 'key.pem')
    certout = os.path.join(outdir, sys.argv[2] + 'cert.pem')
    csrout = None
    try:
        csrout = sys.argv[1]
    except IndexError:
        csrout = None
    create_certificate(keyout, certout, csrout)
