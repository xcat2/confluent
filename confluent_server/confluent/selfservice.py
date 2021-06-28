import confluent.runansible as runansible
import confluent.syncfiles as syncfiles
import confluent.config.configmanager as configmanager
import confluent.collective.manager as collective
import confluent.netutil as netutil
import confluent.noderange as noderange
import confluent.sshutil as sshutil
import confluent.util as util
import eventlet.green.socket as socket
import eventlet.green.subprocess as subprocess
import confluent.discovery.handlers.xcc as xcc
import confluent.discovery.handlers.tsm as tsm
import crypt
import json
import os
import time
import yaml

currtz = None
keymap = 'us'
currlocale = 'en_US.UTF-8'
currtzvintage = None


def yamldump(input):
    return yaml.safe_dump(input, default_flow_style=False)

def get_extra_names(nodename, cfg):
    names = set([])
    dnsinfo = cfg.get_node_attributes(nodename, ('dns.*', 'net.*hostname'))
    dnsinfo = dnsinfo.get(nodename, {})
    domain = dnsinfo.get('dns.domain', {}).get('value', None)
    if domain and domain not in nodename:
        names.add('{0}.{1}'.format(nodename, domain))
    for keyname in dnsinfo:
        if keyname.endswith('hostname'):
            currnames = dnsinfo[keyname].get('value', None)
            if currnames:
                currnames = currnames.split(',')
                for currname in currnames:
                    names.add(currname)
                    if domain and domain not in currname:
                        names.add('{0}.{1}'.format(currname, domain))
    return names

def handle_request(env, start_response):
    global currtz
    global keymap
    global currlocale
    global currtzvintage
    configmanager.check_quorum()
    nodename = env.get('HTTP_CONFLUENT_NODENAME', None)
    apikey = env.get('HTTP_CONFLUENT_APIKEY', None)
    if not (nodename and apikey):
        start_response('401 Unauthorized', [])
        yield 'Unauthorized'
        return
    cfg = configmanager.ConfigManager(None)
    ea = cfg.get_node_attributes(nodename, ['crypted.selfapikey', 'deployment.apiarmed'])
    eak = ea.get(
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
    if ea.get(nodename, {}).get('deployment.apiarmed', {}).get('value', None) == 'once':
        cfg.set_node_attributes({nodename: {'deployment.apiarmed': ''}})
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
    operation = env['REQUEST_METHOD']
    if operation not in ('HEAD', 'GET') and 'CONTENT_LENGTH' in env and int(env['CONTENT_LENGTH']) > 0:
        reqbody = env['wsgi.input'].read(int(env['CONTENT_LENGTH']))
    if env['PATH_INFO'] == '/self/bmcconfig':
        hmattr = cfg.get_node_attributes(nodename, 'hardwaremanagement.*')
        hmattr = hmattr.get(nodename, {})
        res = {}
        port = hmattr.get('hardwaremanagement.port', {}).get('value', None)
        if port is not None:
            res['bmcport'] = port
        vlan = hmattr.get('hardwaremanagement.vlan', {}).get('value', None)
        if vlan is not None:
            res['bmcvlan'] = vlan
        bmcaddr = hmattr.get('hardwaremanagement.manager', {}).get('value',
                                                                   None)
        bmcaddr = socket.getaddrinfo(bmcaddr, 0)[0]
        bmcaddr = bmcaddr[-1][0]
        if '.' in bmcaddr:  # ipv4 is allowed
            netconfig = netutil.get_nic_config(cfg, nodename, ip=bmcaddr)
            res['bmcipv4'] = bmcaddr
            res['prefixv4'] = netconfig['prefix']
            res['bmcgw'] = netconfig.get('ipv4_gateway', None)
        # credential security results in user/password having to be deferred
        start_response('200 OK', (('Content-Type', retype),))
        yield dumper(res)
    elif env['PATH_INFO'] == '/self/deploycfg':
        if 'HTTP_CONFLUENT_MGTIFACE' in env:
            ncfg = netutil.get_nic_config(cfg, nodename, ifidx=env['HTTP_CONFLUENT_MGTIFACE'])
        else:
            myip = env.get('HTTP_X_FORWARDED_HOST', None)
            if ']' in myip:
                myip = myip.split(']', 1)[0]
            else:
                myip = myip.split(':', 1)[0]
            myip = myip.replace('[', '').replace(']', '')
            ncfg = netutil.get_nic_config(cfg, nodename, serverip=myip)
        if ncfg['prefix']:
            ncfg['ipv4_netmask'] = netutil.cidr_to_mask(ncfg['prefix'])
        if ncfg['ipv4_method'] == 'firmwaredhcp':
            ncfg['ipv4_method'] = 'static'
        deployinfo = cfg.get_node_attributes(
            nodename, ('deployment.*', 'console.method', 'crypted.*',
                       'dns.*', 'ntp.*'))
        deployinfo = deployinfo.get(nodename, {})
        profile = deployinfo.get(
            'deployment.pendingprofile', {}).get('value', '')
        ncfg['encryptboot'] = deployinfo.get('deployment.encryptboot', {}).get(
            'value', None)
        if ncfg['encryptboot'] in ('', 'none'):
            ncfg['encryptboot'] = None
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
        ncfg['grubpassword'] = deployinfo.get('crypted.grubpassword', {}).get(
            'grubhashvalue', None)
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
        ntpsrvs = deployinfo.get('ntp.servers', {}).get('value', '')
        if ntpsrvs:
            ntpsrvs = ntpsrvs.split(',')
        if ntpsrvs:
            ncfg['ntpservers'] = []
            for ntpsrv in ntpsrvs:
                ncfg['ntpservers'].append(ntpsrv)
        dnsdomain = deployinfo.get('dns.domain', {}).get('value', None)
        ncfg['dnsdomain'] = dnsdomain
        start_response('200 OK', (('Content-Type', retype),))
        yield dumper(ncfg)
    elif env['PATH_INFO'] == '/self/sshcert' and reqbody:
        if not sshutil.ca_exists():
            start_response('500 Unconfigured', ())
            yield 'CA is not configured on this system (run ...)'
            return
        pals = get_extra_names(nodename, cfg)
        cert = sshutil.sign_host_key(reqbody, nodename, pals)
        start_response('200 OK', (('Content-Type', 'text/plain'),))
        yield cert
    elif env['PATH_INFO'] == '/self/nodelist':
        nodes, _ = get_cluster_list(nodename, cfg)
        if isgeneric:
            start_response('200 OK', (('Content-Type', 'text/plain'),))
            for node in util.natural_sort(nodes):
                yield node + '\n'
        else:
            start_response('200 OK', (('Content-Type', retype),))
            yield dumper(sorted(nodes))
    elif env['PATH_INFO'] == '/self/remoteconfigbmc' and reqbody:
        try:
            reqbody = yaml.safe_load(reqbody)
        except Exception:
            reqbody = None
        cfgmod = reqbody.get('configmod', 'unspecified')
        if cfgmod == 'xcc':
            xcc.remote_nodecfg(nodename, cfg)
        elif cfgmod == 'tsm':
            tsm.remote_nodecfg(nodename, cfg)
        else:
            start_response('500 unsupported configmod', ())
            yield 'Unsupported configmod "{}"'.format(cfgmod)
        start_response('200 Ok', ())
        yield 'complete'
    elif env['PATH_INFO'] == '/self/updatestatus' and reqbody:
        update = yaml.safe_load(reqbody)
        if update['status'] == 'staged':
            targattr = 'deployment.stagedprofile'
        elif update['status'] == 'complete':
            targattr = 'deployment.profile'
        else:
            raise Exception('Unknown update status request')
        currattr = cfg.get_node_attributes(nodename, 'deployment.*').get(
            nodename, {})
        pending = None
        if targattr == 'deployment.profile':
            pending = currattr.get('deployment.stagedprofile', {}).get('value', '')
        if not pending:
            pending = currattr.get('deployment.pendingprofile', {}).get('value', '')
        updates = {}
        if pending:
            updates['deployment.pendingprofile'] = {'value': ''}
            if targattr == 'deployment.profile':
                updates['deployment.stagedprofile'] = {'value': ''}
            currprof = currattr.get(targattr, {}).get('value', '')
            if currprof != pending:
                updates[targattr] = {'value': pending}
            cfg.set_node_attributes({nodename: updates})
            start_response('200 OK', (('Content-Type', 'text/plain'),))
            yield 'OK'
        else:
            start_response('500 Error', (('Content-Type', 'text/plain'),))
            yield 'No pending profile detected, unable to accept status update'
    elif env['PATH_INFO'] == '/self/saveapikey' and reqbody:
        if not isinstance(reqbody, str):
            reqbody = reqbody.decode('utf8')
        cfg.set_node_attributes({
            nodename: {'deployment.sealedapikey': {'value': reqbody}}})
        start_response('200 OK', ())
        yield ''
    elif env['PATH_INFO'].startswith('/self/remoteconfig/') and 'POST' == operation:
        scriptcat = env['PATH_INFO'].replace('/self/remoteconfig/', '')
        slist, profile = get_scriptlist(
            scriptcat, cfg, nodename,
            '/var/lib/confluent/public/os/{0}/ansible/{1}')
        playlist = []
        dirname = '/var/lib/confluent/public/os/{0}/ansible/{1}/'.format(
            profile, scriptcat)
        if not os.path.isdir(dirname):
            dirname = '/var/lib/confluent/public/os/{0}/ansible/{1}.d/'.format(
                profile, scriptcat)
        for filename in slist:
            if filename.endswith('.yaml') or filename.endswith('.yml'):
                playlist.append(os.path.join(dirname, filename))
        if playlist:
            runansible.run_playbooks(playlist, [nodename])
            start_response('202 Queued', ())
            yield ''
        else:
            start_response('200 OK', ())
            yield ''
            return
    elif env['PATH_INFO'].startswith('/self/remotesyncfiles'):
        if 'POST' == operation:
            result = syncfiles.start_syncfiles(
                nodename, cfg, json.loads(reqbody))
            start_response(result, ())
            yield ''
            return
        if 'GET' == operation:
            status, output = syncfiles.get_syncresult(nodename)
            start_response(status, ())
            yield output
            return
    elif env['PATH_INFO'].startswith('/self/remoteconfig/status'):
        rst = runansible.running_status.get(nodename, None)
        if not rst:
            start_response('204 Not Running', (('Content-Length', '0'),))
            yield ''
            return
        start_response('200 OK', ())
        if rst.complete:
            del runansible.running_status[nodename]
        yield rst.dump_text()
        return
    elif env['PATH_INFO'].startswith('/self/scriptlist/'):
        scriptcat = env['PATH_INFO'].replace('/self/scriptlist/', '')
        slist, _ = get_scriptlist(
            scriptcat, cfg, nodename,
            '/var/lib/confluent/public/os/{0}/scripts/{1}')
        if slist:
            start_response('200 OK', (('Content-Type', 'application/yaml'),))
            yield yaml.safe_dump(util.natural_sort(slist), default_flow_style=False)
        else:
            start_response('200 OK', ())
            yield ''
    else:
        start_response('404 Not Found', ())
        yield 'Not found'

def get_scriptlist(scriptcat, cfg, nodename, pathtemplate):
    if '..' in scriptcat:
        return None, None
    deployinfo = cfg.get_node_attributes(
        nodename, ('deployment.*',))
    deployinfo = deployinfo.get(nodename, {})
    profile = deployinfo.get(
        'deployment.pendingprofile', {}).get('value', '')
    if not profile:
        profile = deployinfo.get(
        'deployment.stagedprofile', {}).get('value', '')
    if not profile:
        profile = deployinfo.get(
        'deployment.profile', {}).get('value', '')
    slist = []
    target = pathtemplate.format(profile, scriptcat)
    if not os.path.isdir(target) and os.path.isdir(target + '.d'):
        target = target + '.d'
    try:
        slist = os.listdir(target)
    except OSError:
        pass
    return slist, profile


def get_cluster_list(nodename=None, cfg=None):
    if cfg is None:
        cfg = configmanager.ConfigManager(None)
    nodes = None
    if nodename is not None:
        sshpeers = cfg.get_node_attributes(nodename, 'ssh.trustnodes')
        sshpeers = sshpeers.get(nodename, {}).get('ssh.trustnodes', {}).get(
            'value', None)
        if sshpeers:
            nodes = noderange.NodeRange(sshpeers, cfg).nodes
    autonodes = False
    if nodes is None:
        autonodes = True
        nodes = set(cfg.list_nodes())
    domain = None
    for node in list(util.natural_sort(nodes)):
        if domain is None:
            domaininfo = cfg.get_node_attributes(node, 'dns.domain')
            domain = domaininfo.get(node, {}).get('dns.domain', {}).get(
                'value', None)
        for extraname in get_extra_names(node, cfg):
            nodes.add(extraname)
    if autonodes:
        for mgr in configmanager.list_collective():
            nodes.add(mgr)
            if domain and domain not in mgr:
                nodes.add('{0}.{1}'.format(mgr, domain))
        myname = collective.get_myname()
        nodes.add(myname)
        if domain and domain not in myname:
            nodes.add('{0}.{1}'.format(myname, domain))
    return nodes, domain
