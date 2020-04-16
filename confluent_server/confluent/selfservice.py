import confluent.config.configmanager as configmanager
import confluent.netutil as netutil
import confluent.sshutil as sshutil
import crypt
import json
import yaml


def yamldump(input):
    return yaml.safe_dump(input, default_flow_style=False)


def handle_request(env, start_response):
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
    if retype == '*/*':
        retype = 'application/yaml'
    if retype == 'application/yaml':
        dumper = yamldump
    elif retype == 'application/json':
        dumper = json.dumps
    else:
        start_response('406 Not supported', [])
        yield 'Unsupported content type in ACCEPT: ' + retype
        return
    if 'CONTENT_LENGTH' in env and int(env['CONTENT_LENGTH']) > 0:
        reqbody = env['wsgi.input'].read(int(env['CONTENT_LENGTH']))
    if env['PATH_INFO'] == '/self/deploycfg':
        myip = env.get('HTTP_X_FORWARDED_HOST', None)
        myip = myip.replace('[', '').replace(']', '')
        ncfg = netutil.get_nic_config(cfg, nodename, serverip=myip)
        if ncfg['prefix']:
            ncfg['ipv4_netmask'] = netutil.cidr_to_mask(ncfg['prefix'])
        deployinfo = cfg.get_node_attributes(nodename, 'deployment.*')
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
    else:
        start_response('404 Not Found', ())
        yield 'Not found'