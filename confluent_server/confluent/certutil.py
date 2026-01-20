import os
import confluent.collective.manager as collective
import confluent.util as util
from os.path import exists
import datetime
import shutil
import socket
import tempfile
try:
    import cryptography.x509 as x509
except ImportError:
    x509 = None

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

async def get_ip_addresses():
    lines, _ = await util.check_output('ip', 'addr')
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
    chainpath = None
    with open(path, 'r') as openf:
        webconf = openf.read()
    insection = False
    # we always manipulate the first VirtualHost section
    # since we are managing IP based SANs, then SNI
    # can never match anything but the first VirtualHost
    for line in webconf.split('\n'):
        line = line.strip()
        line = line.split('#')[0]
        if not certpath and line.startswith('SSLCertificateFile'):
            insection = True
            if not certpath:
                _, certpath = line.split(None, 1)
        if not keypath and line.startswith('SSLCertificateKeyFile'):
            insection = True
            _, keypath = line.split(None, 1)
        if not chainpath and line.startswith('SSLCertificateChainFile'):
            insection = True
            _, chainpath = line.split(None, 1)
        if insection and line.startswith('</VirtualHost>'):
            break
    return keypath, certpath, chainpath

def check_nginx_config(path):
    keypath = None
    certpath = None
    # again, we only care about the first server section
    # since IP won't trigger SNI matches down the configuration
    with open(path, 'r') as openf:
        webconf = openf.read()
    for line in webconf.split('\n'):
        if keypath and certpath:
            break
        line = line.strip()
        line = line.split('#')[0]
        for segment in line.split(';'):
            if not certpath and segment.startswith('ssl_certificate'):
                _, certpath = segment.split(None, 1)
            if not keypath and segment.startswith('ssl_certificate_key'):
                _, keypath = segment.split(None, 1)
    if keypath:
        keypath = keypath.strip('"')
    if certpath:
        certpath = certpath.strip('"')
    return keypath, certpath

def get_certificate_paths():
    keypath = None
    certpath = None
    chainpath = None
    ngkeypath = None
    ngbundlepath = None
    if os.path.exists('/etc/httpd/conf.d/ssl.conf'): # redhat way
        keypath, certpath, chainpath = check_apache_config('/etc/httpd/conf.d/ssl.conf')
    if not keypath and os.path.exists('/etc/apache2'): # suse way
        for currpath, _, files in os.walk('/etc/apache2'):
            for fname in files:
                if fname.endswith('.template'):
                    continue
                kploc = check_apache_config(os.path.join(currpath,
                                                                       fname))
                if keypath and kploc[0] and keypath != kploc[0]:
                    return {'error': 'Ambiguous...'}
                if kploc[0]:
                    keypath, certpath, chainpath = kploc
    if os.path.exists('/etc/nginx'): # nginx way
        for currpath, _, files in os.walk('/etc/nginx'):
            if ngkeypath:
                break
            for fname in files:
                if not fname.endswith('.conf'):
                    continue
                ngkeypath, ngbundlepath = check_nginx_config(os.path.join(currpath,
                                                                       fname)) 
                if ngkeypath:
                    break
    tlsmateriallocation = {}
    if keypath:
        tlsmateriallocation.setdefault('keys', []).append(keypath)
    if ngkeypath:
        tlsmateriallocation.setdefault('keys', []).append(ngkeypath)
    if certpath:
        tlsmateriallocation.setdefault('certs', []).append(certpath)
    if chainpath:
        tlsmateriallocation.setdefault('chains', []).append(chainpath)
    if ngbundlepath:
        tlsmateriallocation.setdefault('bundles', []).append(ngbundlepath)
    return tlsmateriallocation

async def assure_tls_ca():
    keyout, certout = ('/etc/confluent/tls/cakey.pem', '/etc/confluent/tls/cacert.pem')
    if not os.path.exists(certout):
        #create_simple_ca(keyout, certout)
        await create_full_ca(certout)
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
        hv, _ = await util.check_output(
            'openssl', 'x509', '-in', '/etc/confluent/tls/cacert.pem', '-hash', '-noout')
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
    return certout

#def is_self_signed(pem):
#    cert = ssl.PEM_cert_to_DER_cert(pem)
#    return cert.get('subjectAltName', []) == cert.get('issuer', [])
# x509 certificate issuer subject comparison..
#>>> b.issuer
#<Name(C=US,ST=NC,L=RTP,O=Lenovo,CN=XCC-7D9D-J102MM2T)>
#>>> b.subject
#<Name(C=US,ST=NC,L=RTP,O=Lenovo,CN=XCC-7D9D-J102MM2T)>


def substitute_cfg(setting, key, val, newval, cfgfile, line):
    if key.strip() == setting:
        cfgfile.write(line.replace(val, newval) + '\n')
        return True
    return False

async def create_full_ca(certout):
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
            cfgfile.write('\n[CACert]\nbasicConstraints = critical,CA:true\nkeyUsage = critical,keyCertSign,cRLSign\n[ca_confluent]\n')
    await util.check_call(
        'openssl', 'ecparam', '-name', 'secp384r1', '-genkey', '-out',
        keyout)
    await util.check_call(
        'openssl', 'req', '-new', '-key', keyout, '-out', csrout, '-subj', subj)
    await util.check_call(
        'openssl', 'ca', '-config', newcfg, '-batch', '-selfsign',
        '-extensions', 'CACert', '-extfile', newcfg, 
        '-notext', '-md', 'sha384', '-startdate',
         '19700101010101Z', '-enddate', '21000101010101Z', '-keyfile',
         keyout, '-out', '/etc/confluent/tls/ca/cacert.pem', '-in', csrout
    )
    shutil.copy2('/etc/confluent/tls/ca/cacert.pem', certout)
#openssl ca -config openssl.cnf -selfsign -keyfile cakey.pem -startdate 20150214120000Z -enddate 20160214120000Z
#20160107071311Z -enddate 20170106071311Z

async def create_simple_ca(keyout, certout):
    try:
        os.makedirs('/etc/confluent/tls')
    except OSError as e:
        if e.errno != 17:
            raise
    sslcfg = get_openssl_conf_location()
    tmphdl, tmpconfig = tempfile.mkstemp()
    os.close(tmphdl)
    shutil.copy2(sslcfg, tmpconfig)
    await util.check_call(
            'openssl', 'ecparam', '-name', 'secp384r1', '-genkey', '-out',
            keyout)
    try:
        subj = '/CN=Confluent TLS Certificate authority ({0})'.format(socket.gethostname())
        if len(subj) > 68:
            subj = subj[:68]
        with open(tmpconfig, 'a') as cfgfile:
            cfgfile.write('\n[CACert]\nbasicConstraints = critical,CA:true\n')
        await util.check_call(
                'openssl', 'req', '-new', '-x509', '-key', keyout, '-days',
                '27300', '-out', certout, '-subj', subj,
                '-extensions', 'CACert', '-config', tmpconfig
            )
    finally:
        os.remove(tmpconfig)

async def create_certificate(keyout=None, certout=None, csrfile=None, subj=None, san=None, backdate=True, days=None):
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    if backdate:
        # To deal with wildly off clocks, we backdate certificates.
        startdate = '20000101010101Z'
    else:
        # apply a mild backdate anyway, even if these are supposed to be for more accurate clocks
        startdate = (now_utc - datetime.timedelta(hours=24)).strftime('%Y%m%d%H%M%SZ')
    if days is None:
        enddate = '21000101010101Z'
    else:
        enddate = (now_utc + datetime.timedelta(days=days)).strftime('%Y%m%d%H%M%SZ')
    tlsmateriallocation = {}
    if not certout:
        tlsmateriallocation = get_certificate_paths()
        keyout = tlsmateriallocation.get('keys', [None])[0]
        certout = tlsmateriallocation.get('certs', [None])[0]
        if not certout:
            certout = tlsmateriallocation.get('bundles', [None])[0]
    if (not keyout and not csrfile) or not certout:
        raise Exception('Unable to locate TLS certificate path automatically')
    cacertname = await assure_tls_ca()
    if not subj:
        shortname = socket.gethostname().split('.')[0]
        longname = shortname # socket.getfqdn()
        subj = '/CN={0}'.format(longname)
    elif '/CN=' not in subj:
        subj = '/CN={0}'.format(subj)
    if not csrfile:
        await util.check_call(
            ['openssl', 'ecparam', '-name', 'secp384r1', '-genkey', '-out',
             keyout])
    permitdomains = []
    if x509:
        # check if this CA has name constraints, and avoid violating them
        with open(cacertname, 'rb') as f:
            cer = x509.load_pem_x509_certificate(f.read())
        for extension in cer.extensions:
            if extension.oid == x509.ExtensionOID.NAME_CONSTRAINTS:
                nc = extension.value
                for pname in nc.permitted_subtrees:
                    permitdomains.append(pname.value)
    if not san:
        ipaddrs = list(get_ip_addresses())
        if not permitdomains:
            san = ['IP:{0}'.format(x) for x in ipaddrs]
            # It is incorrect to put IP addresses as DNS type.  However
            # there exists non-compliant clients that fail with them as IP
            # san.extend(['DNS:{0}'.format(x) for x in ipaddrs])
            dnsnames = set(ipaddrs)
            dnsnames.add(shortname)
            dnsnames.add(longname)
        else:
            # nameconstraints preclude IP and shortname
            san = []
            dnsnames = set()
            for suffix in permitdomains:
                if longname.endswith(suffix):
                    dnsnames.add(longname)
                    break
        for currip in ipaddrs:
            currname = socket.getnameinfo((currip, 0), 0)[0]
            for suffix in permitdomains:
                if currname.endswith(suffix):
                    dnsnames.add(currname)
                    break
            if not permitdomains:
                dnsnames.add(currname)
        for currname in dnsnames:
            san.append('DNS:{0}'.format(currname))
        #san.append('DNS:{0}'.format(longname))
        san = ','.join(san)
    sslcfg = get_openssl_conf_location()
    tmphdl, tmpconfig = tempfile.mkstemp()
    os.close(tmphdl)
    tmphdl, extconfig = tempfile.mkstemp()
    os.close(tmphdl)
    needcsr = False
    if csrfile is None:
        needcsr = True
        tmphdl, csrfile = tempfile.mkstemp()
        os.close(tmphdl)
    shutil.copy2(sslcfg, tmpconfig)
    try:
        with open(extconfig, 'a') as cfgfile:
            cfgfile.write('\nbasicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName={0}'.format(san))
        if needcsr:
            with open(tmpconfig, 'a') as cfgfile:
                cfgfile.write('\n[SAN]\nsubjectAltName={0}'.format(san))
            await util.check_call(
                'openssl', 'req', '-new', '-key', keyout, '-out', csrfile, '-subj',
                subj, '-extensions', 'SAN', '-config', tmpconfig
            )
        #else:
        #    # when used manually, allow the csr SAN to stand
        #    # may add explicit subj/SAN argument, in which case we would skip copy
        #    #with open(tmpconfig, 'a') as cfgfile:
        #    #    cfgfile.write('\ncopy_extensions=copy\n')
        #    with open(extconfig, 'a') as cfgfile:
        #        cfgfile.write('\nbasicConstraints=CA:false\n')
        if os.path.exists('/etc/confluent/tls/cakey.pem'):
            # simple style CA in effect, make a random serial number and
            # hope for the best, and accept inability to backdate the cert
            serialnum = '0x' + ''.join(['{:02x}'.format(x) for x in bytearray(os.urandom(20))])
            await util.check_call(
                'openssl', 'x509', '-req', '-in', csrfile,
                '-CA', '/etc/confluent/tls/cacert.pem',
                '-CAkey', '/etc/confluent/tls/cakey.pem',
                '-set_serial', serialnum, '-out', certout, '-days', '27300',
                '-extfile', extconfig
            )
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
            await util.check_call(
                'openssl', 'ca', '-config', cacfgfile, '-rand_serial',
                '-in', csrfile, '-out', certout, '-batch', '-notext',
                '-startdate', startdate, '-enddate', enddate, '-md', 'sha384',
                '-extfile', extconfig, '-subj', subj
            )
        for keycopy in tlsmateriallocation.get('keys', []):
            if keycopy != keyout:
                shutil.copy2(keyout, keycopy)
        for certcopy in tlsmateriallocation.get('certs', []):
            if certcopy != certout:
                shutil.copy2(certout, certcopy)
        cacert = None
        with open('/etc/confluent/tls/cacert.pem', 'rb') as cacertfile:
            cacert = cacertfile.read()
        for bundlecopy in tlsmateriallocation.get('bundles', []):
            if bundlecopy != certout:
                shutil.copy2(certout, bundlecopy)
            with open(bundlecopy, 'ab') as bundlefile:
                bundlefile.write(b'\n')
                bundlefile.write(cacert)
        for chaincopy in tlsmateriallocation.get('chains', []):
            if chaincopy != certout:
                with open(chaincopy, 'wb') as chainfile:
                    chainfile.write(cacert)
            else:
                with open(chaincopy, 'ab') as chainfile:
                    chainfile.write(b'\n')
                    chainfile.write(cacert)
    finally:
        os.remove(tmpconfig)
        if needcsr:
            os.remove(csrfile)
        os.remove(extconfig)


if __name__ == '__main__':
    import sys
    outdir = os.getcwd()
    keyout = os.path.join(outdir, 'key.pem')
    certout = os.path.join(outdir, 'cert.pem')
    csrout = None
    subj, san = (None, None)
    try:
        bindex = sys.argv.index('-b')
        bmcnode = sys.argv.pop(bindex + 1)  # Remove bmcnode argument
        sys.argv.pop(bindex)      # Remove -b flag
        import confluent.config.configmanager as cfm
        c = cfm.ConfigManager(None)
        subj, san = util.get_bmc_subject_san(c, bmcnode)
    except ValueError:
        bindex = None
    try:
        csrout = sys.argv[1]
    except IndexError:
        csrout = None
    create_certificate(keyout, certout, csrout, subj, san, backdate=False, days=3650)
