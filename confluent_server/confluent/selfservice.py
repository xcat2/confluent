import confluent.config.configmanager as configmanager
import confluent.collective.manager as collective
import confluent.netutil as netutil
import confluent.sshutil as sshutil
import confluent.util as util
import eventlet.green.subprocess as subprocess
import crypt
import json
import time
import yaml

currtz = None
currtzvintage = None


def yamldump(input):
    return yaml.safe_dump(input, default_flow_style=False)


def handle_request(env, start_response):
    global currtz
    global currtzvintage
    nodename = env.get('HTTP_CONFLUENT_NODENAME', None)
    apikey = env.get('HTTP_CONFLUENT_APIKEY', None)
    if not (nodename and apikey):
        start_response('401 Unauthorized', [])
        yield 'Unauthorized'
        return
    cfg = configmanager.ConfigManager(None)
    eak = cfg.get_node_attributes(nodename, 'deployment.apikey').get(
        nodename, {}).get('deployment.apikey', {}).get('value', None)
    if not eak:
        start_response('401 Unauthorized', [])
        yield 'Unauthorized'
        return
    salt = '$'.join(eak.split('$', 3)[:-1]) + '$'
    if crypt.crypt(apikey, salt) != eak:
        start_response('401 Unauthorized', [])
        yield 'Unauthorized'
        return
    retype = env.get('HTTP_ACCEPT', 'application/yaml')
    isgeneric = False
    if retype == '*/*':
        isgeneric = True
        retype = 'application/yaml'
    if retype == 'application/yaml':
        dumper = yamldump
    elif retype == 'application/json':
        dumper = json.dumps
    else:
        start_response('406 Not supported', [])
        yield 'Unsupported content type in ACCEPT: ' + retype
        return
    if env['REQUEST_METHOD'] not in ('HEAD', 'GET') and 'CONTENT_LENGTH' in env and int(env['CONTENT_LENGTH']) > 0:
        reqbody = env['wsgi.input'].read(int(env['CONTENT_LENGTH']))
    if env['PATH_INFO'] == '/self/deploycfg':
        myip = env.get('HTTP_X_FORWARDED_HOST', None)
        myip = myip.replace('[', '').replace(']', '')
        ncfg = netutil.get_nic_config(cfg, nodename, serverip=myip)
        if ncfg['prefix']:
            ncfg['ipv4_netmask'] = netutil.cidr_to_mask(ncfg['prefix'])
        deployinfo = cfg.get_node_attributes(
            nodename, ('deployment.*', 'crypted.rootpassword', 'services.*'))
        deployinfo = deployinfo.get(nodename, {})
        profile = deployinfo.get(
            'deployment.pendingprofile', {}).get('value', '')
        ncfg['profile'] = profile
        protocol = deployinfo.get('deployment.useinsecureprotocols', {}).get(
            'value', 'never')
        if protocol == 'always':
            ncfg['protocol'] = 'http'
        else:
            ncfg['protocol'] = 'https'
        ncfg['rootpassword'] = deployinfo.get('crypted.rootpassword', {}).get(
            'hashvalue', None)
        if currtzvintage and currtzvintage > (time.time() - 30.0):
            ncfg['timezone'] = currtz
        else:
            tdc = subprocess.check_output(['timedatectl']).split(b'\n')
            for ent in tdc:
                ent = ent.strip()
                if ent.startswith(b'Time zone:'):
                    currtz = ent.split(b': ', 1)[1].split(b'(', 1)[0].strip()
                    if not isinstance(currtz, str):
                        currtz = currtz.decode('utf8')
                    currtzvintage = time.time()
                    ncfg['timezone'] = currtz
                    break
        ncfg['nameservers'] = []
        for dns in deployinfo.get(
                'services.dns', {}).get('value', '').split(','):
            ncfg['nameservers'].append(dns)
        start_response('200 OK', (('Content-Type', retype),))
        yield dumper(ncfg)
    elif env['PATH_INFO'] == '/self/sshcert':
        if not sshutil.ca_exists():
            start_response('500 Unconfigured', ())
            yield 'CA is not configured on this system (run ...)'
            return
        cert = sshutil.sign_host_key(reqbody, nodename)
        start_response('200 OK', (('Content-Type', 'text/plain'),))
        yield cert
    elif env['PATH_INFO'] == '/self/nodelist':
        nodes = set(cfg.list_nodes())
        for mgr in configmanager.list_collective():
            nodes.add(mgr)
        nodes.add(collective.get_myname())
        if isgeneric:
            start_response('200 OK', (('Contennt-Type', 'text/plain'),))
            for node in util.natural_sort(nodes):
                yield node + '\n'
        else:
            start_response('200 OK', (('Content-Type', retype),))
            yield dumper(sorted(nodes))

    else:
        start_response('404 Not Found', ())
        yield 'Not found'