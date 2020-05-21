#!/usr/bin/python

import confluent.collective.manager as collective
import eventlet.green.subprocess as subprocess
import glob
import os
import shutil
import tempfile

def normalize_uid():
    curruid = os.getuid()
    neededuid = os.stat('/etc/confluent').st_uid
    if curruid != neededuid:
        os.setuid(neededuid)
    if os.getuid() != neededuid:
        raise Exception('Need to run as root or owner of /etc/confluent')


def initialize_ca():
    normalize_uid()
    try:
        os.makedirs('/etc/confluent/ssh', mode=0o700)
    except OSError as e:
        if e.errno != 17:
            raise
    myname = collective.get_myname()
    caname = '{0} SSH CA'.format(myname)
    subprocess.check_call(['ssh-keygen', '-C', caname, '-t', 'ed25519', '-f', '/etc/confluent/ssh/ca', '-N', ''])
    try:
        os.makedirs('/var/lib/confluent/public/site/ssh/', mode=0o755)
    except OSError as e:
        if e.errno != 17:
            raise
    cafilename = '/var/lib/confluent/public/site/ssh/{0}.ca'.format(myname)
    shutil.copy('/etc/confluent/ssh/ca.pub', cafilename)
    #    newent = '@cert-authority * ' + capub.read()


def sign_host_key(pubkey, nodename):
    tmpdir = tempfile.mkdtemp()
    try:
        pkeyname = os.path.join(tmpdir, 'hostkey.pub')
        with open(pkeyname, 'wb') as pubfile:
            pubfile.write(pubkey)
        subprocess.check_call(
            ['ssh-keygen', '-s', '/etc/confluent/ssh/ca', '-I', nodename,
             '-n', nodename, '-h', pkeyname])
        certname = pkeyname.replace('.pub', '-cert.pub')
        with open(certname) as cert:
            return cert.read()
    finally:
        shutil.rmtree(tmpdir)

def initialize_root_key(generate):
    authorized = []
    myname = collective.get_myname()
    for currkey in glob.glob('/root/.ssh/*.pub'):
        authorized.append(currkey)
    if generate and not authorized:
        subprocess.check_call(['ssh-keygen', '-t', 'ed25519', '-f', '/root/.ssh/id_ed25519', '-N', ''])
        for currkey in glob.glob('/root/.ssh/*.pub'):
            authorized.append(currkey)
    try:
        os.makedirs('/var/lib/confluent/public/site/ssh', mode=0o755)
        neededuid = os.stat('/etc/confluent').st_uid
        os.chown('/var/lib/confluent/public/site/ssh', neededuid, -1)
    except OSError as e:
        if e.errno != 17:
            raise
    neededuid = os.stat('/etc/confluent').st_uid
    for auth in authorized:
        shutil.copy(
            auth,
            '/var/lib/confluent/public/site/ssh/{0}.rootpubkey'.format(
                    myname))
        os.chmod('/var/lib/confluent/public/site/ssh/{0}.rootpubkey'.format(
                myname), 0o644)
        os.chown('/var/lib/confluent/public/site/ssh/{0}.rootpubkey'.format(
                myname), neededuid, -1)


def ca_exists():
    return os.path.exists('/etc/confluent/ssh/ca')


if __name__ == '__main__':
    initialize_root_key(True)
    if not ca_exists():
        initialize_ca()
    print(repr(sign_host_key(open('/etc/ssh/ssh_host_ed25519_key.pub').read(), collective.get_myname())))