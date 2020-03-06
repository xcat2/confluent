#!/usr/bin/python

import confluent.collective.manager as collective
import eventlet.green.subprocess as subprocess
import os

def initialize_ca():
    try:
        os.makedirs('/etc/confluent/ssh', mode=0o600)
    except OSError as e:
        if e.errno != 17:
            raise
    caname = '{0} SSH CA'.format(collective.get_myname())
    subprocess.check_call(['ssh-keygen', '-C', caname, '-t', 'ecdsa', '-f', '/etc/confluent/ssh/ca', '-N', ''])


def ca_exists():
    return os.path.exists('/etc/confluent/ssh/ca')


if __name__ == '__main__':
    if not ca_exists():
        initialize_ca()