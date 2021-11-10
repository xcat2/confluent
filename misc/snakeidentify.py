import argparse
import confluent.client as cli
import sys
import time
c = cli.Command()
nodes = []
ap = argparse.ArgumentParser(description='Snake identify light through nodes')
ap.add_argument('noderange', help='Noderange to iterate through')
ap.add_argument('-d', '--duration', type=float, help='How long to have each system illuminated')
args = ap.parse_args()

def runit(itera):
    for rsp in itera:
        if 'error' in rsp:
            sys.stderr.write('{0}\n'.format(repr(rsp)))

for ret in c.read('/noderange/{0}/nodes/'.format(args.noderange)):
    node = ret.get('item', {}).get('href', None)
    if node:
        node = node.replace('/', '')
        nodes.append(node)
    else:
        print(repr(ret))
if not nodes:
    sys.exit(1)
lastnode = None
interval = args.duration
if interval:
    interval = interval / 2
else:
    interval = 0.25
while True:
    for node in nodes:
        print('Lighting {0}'.format(node))
        runit(c.update('/nodes/{0}/identify'.format(node), {'identify': 'on'}))
        time.sleep(interval)
        if lastnode:
            runit(c.update('/nodes/{0}/identify'.format(lastnode), {'identify': 'off'}))
        lastnode = node
        time.sleep(interval)

