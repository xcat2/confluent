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
keymap = 'us'
currlocale = 'en_US.UTF-8'
currtzvintage = None


def yamldump(input):
    return yaml.safe_dump(input, default_flow_style=False)


def handle_request(env, start_response):
    global currtz
    global keymap
    global currlocale
    global currtzvintage
    nodename = env.get('HTTP_CONFLUENT_NODENAME', None)
    apikey = env.get('HTTP_CONFLUENT_APIKEY', None)
    if not (nodename and apikey):
        start_response('401 Unauthorized', [])
        yield 'Unauthorized'
        return
    cfg = configmanager.ConfigManager(None)
    eak = cfg.get_node_attributes(nodename, 'crypted.selfapikey').get(
        nodename, {}).get('crypted.selfapikey', {}).get('hashvalue', None)
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
            nodename, ('deployment.*', 'console.method', 'crypted.rootpassword',
                       'dns.*'))
        deployinfo = deployinfo.get(nodename, {})
        profile = deployinfo.get(
            'deployment.pendingprofile', {}).get('value', '')
        ncfg['profile'] = profile
        protocol = deployinfo.get('deployment.useinsecureprotocols', {}).get(
            'value', 'never')
        ncfg['textconsole'] = bool(deployinfo.get(
                                  'console.method', {}).get('value', None))
        if protocol == 'always':
            ncfg['protocol'] = 'http'
        else:
            ncfg['protocol'] = 'https'
        ncfg['rootpassword'] = deployinfo.get('crypted.rootpassword', {}).get(
            'hashvalue', None)
        if currtzvintage and currtzvintage > (time.time() - 30.0):
            ncfg['timezone'] = currtz
        else:
            langinfo = subprocess.check_output(
                ['localectl', 'status']).split(b'\n')
            for line in langinfo:
                line = line.strip()
                if line.startswith(b'System Locale:'):
                    ccurrlocale = line.split(b'=')[-1]
                    if not ccurrlocale:
                        continue
                    if not isinstance(ccurrlocale, str):
                        ccurrlocale = ccurrlocale.decode('utf8')
                    if ccurrlocale == 'n/a':
                        continue
                    currlocale = ccurrlocale
                elif line.startswith(b'VC Keymap:'):
                    ckeymap = line.split(b':')[-1]
                    ckeymap = ckeymap.strip()
                    if not ckeymap:
                        continue
                    if not isinstance(ckeymap, str):
                        ckeymap = ckeymap.decode('utf8')
                    if ckeymap == 'n/a':
                        continue
                    keymap = ckeymap
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
        ncfg['locale'] = currlocale
        ncfg['keymap'] = keymap
        ncfg['nameservers'] = []
        for dns in deployinfo.get(
                'dns.servers', {}).get('value', '').split(','):
            ncfg['nameservers'].append(dns)
        dnsdomain = deployinfo.get('dns.domain', {}).get('value', None)
        ncfg['dnsdomain'] = dnsdomain
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
            start_response('200 OK', (('Content-Type', 'text/plain'),))
            for node in util.natural_sort(nodes):
                yield node + '\n'
        else:
            start_response('200 OK', (('Content-Type', retype),))
            yield dumper(sorted(nodes))
    elif env['PATH_INFO'] == '/self/updatestatus':
        update = yaml.safe_load(reqbody)
        if update['status'] != 'complete':
            raise Exception('Unknown update status request')
        currattr = cfg.get_node_attributes(nodename, 'deployment.*').get(
            nodename, {})
        pending = currattr.get('deployment.pendingprofile', {}).get('value', '')
        updates = {}
        if pending:
            updates['deployment.pendingprofile'] = {'value': ''}
            currprof = currattr.get('deployment.profile', {}).get('value', '')
            if currprof != pending:
                updates['deployment.profile'] = {'value': pending}
            cfg.set_node_attributes({nodename: updates})
            start_response('200 OK', (('Content-Type', 'text/plain'),))
            yield 'OK'
        else:
            start_response('500 Error', (('Content-Type', 'text/plain'),))
            yield 'No pending profile detected, unable to accept status update'
    else:
        start_response('404 Not Found', ())
        yield 'Not found'
