# This creates a locked down variant of a confluent CA

# The confluent CA naturally doesn't have any name constraints, which
# is great for flexibility.

# However, if actually being imported into a web browser, it is likely
# to want to limit the CA to apply to cluster resources rather
# than having a blank check to vouch for any and all subjects.

# This particular approach causes a certificate authority that
# can be imported and vouch for the subset of certificates
# that were issued by the normal CA that match name constraints

# Unfortunately, *ALL* names are checked, whether they are relevant
# to the conversation or not, so we reproduce the logic and the resultant
# CA is fragile to IP addresses.

# The better approach would be to issue a separate, full name only certificate
# and have a simpler alt CA.  The same CA can be used to sign both certificates,
# and still import the limited one


import subprocess
import socket
import confluent.certutil as certutil
import sys
def create_alt_ca(certout, permitdomains):
    # This is to create a constrained variant of the existing authority
    # this will allow a client browser to only trust it for select domains
    # while the nodes can more broadly trust it (e.g. to vouch for IP addresses)
    sslcfg = certutil.get_openssl_conf_location()
    newcfg = '/etc/confluent/tls/ca-alt/openssl-alt.cfg'
    subj = subprocess.check_output(
        ['openssl', 'x509', '-subject', '-noout', '-in', '/etc/confluent/tls/ca/cacert.pem']
        ).decode().replace('subject=', '')
    serial = subprocess.check_output(
        ['openssl', 'x509', '-serial', '-noout', '-in', '/etc/confluent/tls/ca/cacert.pem']
        ).decode().replace('serial=', '')
    with open('/etc/confluent/tls/ca-alt/serial', 'w') as srl:
        srl.write(serial)
    settings = {
        'dir': '/etc/confluent/tls/ca-alt',
        'certificate': '$dir/cacert.pem',
        'private_key': '$dir/private/cakey.pem',
        'countryName': 'optional',
        'stateOrProvinceName': 'optional',
        'organizationName': 'optional',
    }
    keyin = '/etc/confluent/tls/ca/private/cakey.pem'
    csrin = '/etc/confluent/tls/ca/ca.csr'

    shortname = 'r3u20'


    ipaddrs = list(certutil.get_ip_addresses())
    san = [] # 'IP:{0}'.format(x) for x in ipaddrs]
    # It is incorrect to put IP addresses as DNS type.  However
    # there exists non-compliant clients that fail with them as IP
    # san.extend(['DNS:{0}'.format(x) for x in ipaddrs])
    dnsnames = set(ipaddrs)
    dnsnames.add(shortname)
    for currip in ipaddrs:
        dnsnames.add(socket.getnameinfo((currip, 0), 0)[0])
    for currname in dnsnames:
        san.append('DNS:{0}'.format(currname))



    if permitdomains[0] == '':
        permitdomains = []
    nameconstraints = ['permitted;DNS:{}'.format(x) for x in permitdomains]
    nameconstraints.extend(['permitted;{}'.format(x) for x in san])
    nameconstraints = ','.join(nameconstraints)
    if nameconstraints:
        nameconstraints = f'nameConstraints = critical,{nameconstraints}\n'
    certutil.mkdirp('/etc/confluent/tls/ca-alt/newcerts')
    with open('/etc/confluent/tls/ca-alt/index.txt', 'w') as idx:
        pass

    with open(sslcfg, 'r') as cfgin:
        with open(newcfg, 'w') as cfgfile:
            for line in cfgin.readlines():
                cfg = line.split('#')[0]
                if '=' in cfg:
                    key, val = cfg.split('=', 1)
                    for stg in settings:
                        if certutil.substitute_cfg(stg, key, val, settings[stg], cfgfile, line):
                            break
                    else:
                        cfgfile.write(line.strip() + '\n')
                    continue
                cfgfile.write(line.strip() + '\n')
            cfgfile.write(f'\n[CACert]\nbasicConstraints = CA:true\n{nameconstraints}[ca_confluent]\n')
    subprocess.check_call(
        ['openssl', 'ca', '-config', newcfg, '-batch', '-selfsign',
        '-extensions', 'CACert', '-extfile', newcfg,
        '-notext', '-startdate',
         '19700101010101Z', '-enddate', '21000101010101Z', '-keyfile',
         keyin, '-out', certout, '-in', csrin]
    )
if __name__ == '__main__':
    create_alt_ca(sys.argv[1], sys.argv[2].split(','))

