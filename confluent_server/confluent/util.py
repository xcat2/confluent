# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 IBM Corporation
# Copyright 2015-2017 Lenovo
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Various utility functions that do not neatly fit into one category or another
import base64
import confluent.exceptions as cexc
import confluent.log as log
import glob
import hashlib
import ipaddress
try:
    import psutil
except ImportError:
    psutil = None
    import netifaces
import os
import re
import socket
import ssl
import struct
import eventlet.green.subprocess as subprocess
import cryptography.x509 as x509
try:
    import cryptography.x509.verification as verification
except ImportError:
    verification = None



def mkdirp(path, mode=0o777):
    try:
        os.makedirs(path, mode)
    except OSError as e:
        if e.errno != 17:
            raise


def run(cmd):
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    retcode = process.poll()
    if retcode:
        raise subprocess.CalledProcessError(retcode, process.args, output=stdout, stderr=stderr)
    return stdout, stderr


def stringify(instr):
    # Normalize unicode and bytes to 'str', correcting for
    # current python version
    if isinstance(instr, bytes) and not isinstance(instr, str):
        return instr.decode('utf-8', errors='replace')
    elif not isinstance(instr, bytes) and not isinstance(instr, str):
        return instr.encode('utf-8')
    return instr

def list_interface_indexes():
    # Getting the interface indexes in a portable manner
    # would be better, but there's difficulty from a python perspective.
    # For now be linux specific
    try:
        for iface in os.listdir('/sys/class/net/'):
            if not os.path.exists('/sys/class/net/{0}/ifindex'.format(iface)):
                continue
            if os.path.exists('/sys/class/net/{0}/bonding_slave'.format(iface)):
                continue
            ifile = open('/sys/class/net/{0}/ifindex'.format(iface), 'r')
            intidx = int(ifile.read())
            ifile.close()
            yield intidx
    except (IOError, OSError):
        # Probably situation is non-Linux, just do limited support for
        # such platforms until other people come along
        for iface in netifaces.interfaces():
            addrinfo = netifaces.ifaddresses(iface).get(socket.AF_INET6, [])
            for addr in addrinfo:
                v6addr = addr.get('addr', '').partition('%')[2]
                if v6addr:
                    yield(int(v6addr))
                    break
        return


def get_bmc_subject_san(configmanager, nodename, addnames=()):
    bmc_san = []
    subject = ''
    ipas = set([])
    dnsnames = set([])
    for addname in addnames:
        try:
            addr = ipaddress.ip_address(addname)
            ipas.add(addname)
        except Exception:
            dnsnames.add(addname)
    nodecfg = configmanager.get_node_attributes(nodename,
                                             ('dns.domain', 'hardwaremanagement.manager', 'hardwaremanagement.manager_tls_name'))
    bmcaddr = nodecfg.get(nodename, {}).get('hardwaremanagement.manager', {}).get('value', '')
    domain = nodecfg.get(nodename, {}).get('dns.domain', {}).get('value', '')
    isipv4 = False
    if bmcaddr:
        bmcaddr = bmcaddr.split('/', 1)[0]
        bmcaddr = bmcaddr.split('%', 1)[0]
        dnsnames.add(bmcaddr)
        subject = bmcaddr
        if ':' in bmcaddr:
            ipas.add(bmcaddr)
            dnsnames.add('{0}.ipv6-literal.net'.format(bmcaddr.replace(':', '-')))
        else:
            try:
                socket.inet_aton(bmcaddr)
                isipv4 = True
                ipas.add(bmcaddr)
            except socket.error:
                pass
            if not isipv4: # neither ipv6 nor ipv4, should be a name
                if domain and domain not in bmcaddr:
                    dnsnames.add('{0}.{1}'.format(bmcaddr, domain))
    bmcname = nodecfg.get(nodename, {}).get('hardwaremanagement.manager_tls_name', {}).get('value', '')
    if bmcname:
        subject = bmcname
        dnsnames.add(bmcname)
        if domain and domain not in bmcname:
            dnsnames.add('{0}.{1}'.format(bmcname, domain))
    for dns in dnsnames:
        bmc_san.append('DNS:{0}'.format(dns))
    for ip in ipas:
        bmc_san.append('IP:{0}'.format(ip))
    return subject, ','.join(bmc_san)


def list_ips():
    # Used for getting addresses to indicate the multicast address
    # as well as getting all the broadcast addresses
    if psutil:
        ifas = psutil.net_if_addrs()
        for intf in ifas:
            for addr in ifas[intf]:
                if addr.family == socket.AF_INET and addr.broadcast:
                    yield {'broadcast': addr.broadcast, 'addr': addr.address}
    else:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    yield addr

def randomstring(length=20):
    """Generate a random string of requested length

    :param length: The number of characters to produce, defaults to 20
    """
    chunksize = length // 4
    if length % 4 > 0:
        chunksize += 1
    strval = base64.urlsafe_b64encode(os.urandom(chunksize * 3))
    return stringify(strval[0:length])


def securerandomnumber(low=0, high=4294967295):
    """Return a random number within requested range

    Note that this function will not return smaller than 0 nor larger
    than 2^32-1 no matter what is requested.
    The python random number facility does not provide characteristics
    appropriate for secure rng, go to os.urandom

    :param low: Smallest number to return (defaults to 0)
    :param high: largest number to return (defaults to 2^32-1)
    """
    number = -1
    while number < low or number > high:
        number = struct.unpack("I", os.urandom(4))[0]
    return number


def monotonic_time():
    """Return a monotoc time value

    In scenarios like timeouts and such, monotonic timing is preferred.
    """
    # for now, just support POSIX systems
    return os.times()[4]


def get_certificate_from_file(certfile):
    cert = open(certfile, 'r').read()
    inpemcert = False
    prunedcert = ''
    for line in cert.split('\n'):
        if '-----BEGIN CERTIFICATE-----' in line:
            inpemcert = True
        if inpemcert:
            prunedcert += line
        if '-----END CERTIFICATE-----' in line:
            break
    return ssl.PEM_cert_to_DER_cert(prunedcert)


def get_fingerprint(certificate, algo='sha512'):
    if algo == 'sha256':
        return 'sha256$' + hashlib.sha256(certificate).hexdigest()
    elif algo == 'sha512':
        return 'sha512$' + hashlib.sha512(certificate).hexdigest()
    elif algo == 'sha384':
        return 'sha384$' + hashlib.sha384(certificate).hexdigest()
    raise Exception('Unsupported fingerprint algorithm ' + algo)


hashlens = {
    48: hashlib.sha384,
    64: hashlib.sha512,
    32: hashlib.sha256
}

def cert_matches(fingerprint, certificate):
    if not fingerprint or not certificate:
        return False
    if '$' not in fingerprint:
        fingerprint = base64.b64decode(fingerprint)
        algo = hashlens[len(fingerprint)]
        return algo(certificate).digest() == fingerprint
    algo, _, fp = fingerprint.partition('$')
    newfp = None
    if algo in ('sha512', 'sha256', 'sha384'):
        newfp = get_fingerprint(certificate, algo)
    return newfp and fingerprint == newfp


_polbuilder = None


class TLSCertVerifier(object):
    def __init__(self, configmanager, node, fieldname, subject=None):
        self.cfm = configmanager
        self.node = node
        self.fieldname = fieldname
        self.subject = subject

    def verify_by_ca(self, certificate):
        global _polbuilder
        _polbuilder = None
        if not _polbuilder:
            certs = []
            for cert in glob.glob('/var/lib/confluent/public/site/tls/*.pem'):
                with open(cert, 'rb') as certfile:
                    certs.extend(x509.load_pem_x509_certificates(certfile.read()))
            if not certs:
                return False
            castore = verification.Store(certs)
            _polbuilder = verification.PolicyBuilder()
            eep = verification.ExtensionPolicy.permit_all().require_present(
                x509.SubjectAlternativeName, verification.Criticality.AGNOSTIC, None).may_be_present(
                x509.KeyUsage, verification.Criticality.AGNOSTIC, None)
            cap = verification.ExtensionPolicy.webpki_defaults_ca().require_present(
                x509.BasicConstraints, verification.Criticality.AGNOSTIC, None).may_be_present(
                x509.KeyUsage, verification.Criticality.AGNOSTIC, None)
            _polbuilder = _polbuilder.store(castore).extension_policies(
                ee_policy=eep, ca_policy=cap)
        try:
            addr = ipaddress.ip_address(self.subject)
            subject = x509.IPAddress(addr)
        except ValueError:
            subject = x509.DNSName(self.subject)
        cert = x509.load_der_x509_certificate(certificate)
        _polbuilder.build_server_verifier(subject).verify(cert, [])
        return True
        


    def verify_cert(self, certificate):
        storedprint = self.cfm.get_node_attributes(self.node, (self.fieldname,)
                                                   )
        
        if (self.fieldname not in storedprint[self.node] or
                storedprint[self.node][self.fieldname]['value'] == ''):
            # no stored value, check policy for next action
            newpolicy = self.cfm.get_node_attributes(self.node,
                                                     ('pubkeys.addpolicy',))
            if ('pubkeys.addpolicy' in newpolicy[self.node] and
                    'value' in newpolicy[self.node]['pubkeys.addpolicy'] and
                    newpolicy[self.node]['pubkeys.addpolicy']['value'] == 'manual'):
                # manual policy means always raise unless a match is set
                # manually
                fingerprint = get_fingerprint(certificate, 'sha256')
                raise cexc.PubkeyInvalid('New certificate detected',
                                         certificate, fingerprint,
                                         self.fieldname, 'newkey')
            # since the policy is not manual, go ahead and add new key
            # after logging to audit log
            fingerprint = get_fingerprint(certificate, 'sha256')
            auditlog = log.Logger('audit')
            auditlog.log({'node': self.node, 'event': 'certautoadd',
                          'fingerprint': fingerprint})
            self.cfm.set_node_attributes(
                {self.node: {self.fieldname: fingerprint}})
            return True
        elif cert_matches(storedprint[self.node][self.fieldname]['value'],
                          certificate):
            return True
        fingerprint = get_fingerprint(certificate, 'sha256')
        # Mismatches, but try more traditional validation using the site CAs
        if self.subject:
            try:
                if verification and self.verify_by_ca(certificate):
                    auditlog = log.Logger('audit')
                    auditlog.log({'node': self.node, 'event': 'certautoupdate',
                                  'fingerprint': fingerprint})
                    self.cfm.set_node_attributes(
                        {self.node: {self.fieldname: fingerprint}})
                    return True
            except Exception:
                pass
        raise cexc.PubkeyInvalid(
            'Mismatched certificate detected', certificate, fingerprint,
            self.fieldname, 'mismatch')

numregex = re.compile('([0-9]+)')

def naturalize_string(key):
    """Analyzes string in a human way to enable natural sort

    :param nodename: The node name to analyze
    :returns: A structure that can be consumed by 'sorted'
    """
    return [int(text) if text.isdigit() else text.lower()
            for text in re.split(numregex, key)]

def natural_sort(iterable):
    """Return a sort using natural sort if possible

    :param iterable:
    :return:
    """
    try:
        return sorted(iterable, key=naturalize_string)
    except TypeError:
        # The natural sort attempt failed, fallback to ascii sort
        return sorted(iterable)
