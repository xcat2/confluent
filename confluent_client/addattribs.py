#!/usr/bin/python
import os
import sys
path = os.path.dirname(os.path.realpath(__file__))
try:
    sys.path.remove(path)
except Exception:
    pass
path = os.path.realpath(os.path.join(path, '..', 'confluent_server'))
sys.path.append(path)

import confluent.config.attributes as attr
import shutil

shutil.copyfile('doc/man/nodeattrib.ronn.tmpl', 'doc/man/nodeattrib.ronn')
shutil.copyfile('doc/man/nodegroupattrib.ronn.tmpl', 'doc/man/nodegroupattrib.ronn')
with open('doc/man/nodeattrib.ronn', 'a') as outf:
    for field in sorted(attr.node):
        outf.write('\n* `{0}`:\n  {1}\n'.format(field, attr.node[field]['description']))
with open('doc/man/nodegroupattrib.ronn', 'a') as outf:
    for field in sorted(attr.node):
        outf.write('\n* `{0}`:\n  {1}\n'.format(field, attr.node[field]['description']))


