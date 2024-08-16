import asyncio
import confluent.runansible as runansible
import confluent.syncfiles as syncfiles
import confluent.config.configmanager as configmanager
import confluent.collective.manager as collective
import confluent.netutil as netutil
import confluent.noderange as noderange
import confluent.sshutil as sshutil
import confluent.util as util
import confluent.discovery.handlers.xcc as xcc
import confluent.discovery.handlers.tsm as tsm
import confluent.discovery.core as disco
import base64
import hmac
import hashlib
import crypt
import json
import os
import time
import yaml
try:
    from yaml import CSafeDumper as SafeDumper
    from yaml import CSafeLoader as SafeLoader
except ImportError:
    from yaml import SafeLoader
    from yaml import SafeDumper
import confluent.discovery.protocols.ssdp as ssdp
import subprocess
import aiohmi.util.webclient as webclient


currtz = 'UTC'
keymap = 'us'
currlocale = 'en_US.UTF-8'
currtzvintage = None


def yamldump(input):
    return yaml.dump_all([input], Dumper=SafeDumper, default_flow_style=False)

def yamlload(input):
    return yaml.load(input, Loader=SafeLoader)

def listdump(input):
    # special case yaml for flat dumb list
    # this is about 25x faster than doing full yaml dump even with CSafeDumper
    # with a 17,000 element list
    retval = ''
    for entry in input:
        retval += '- ' + entry + '\n'
    return retval


def get_extra_names(nodename, cfg, myip=None):
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
    if myip:
        ncfgs = [netutil.get_nic_config(cfg, nodename, serverip=myip)]
        fncfg = netutil.get_full_net_config(cfg, nodename, serverip=myip)
        ncfgs.append(fncfg.get('default', {}))
        for ent in fncfg.get('extranets', []):
            ncfgs.append(fncfg['extranets'][ent])
        for ncfg in ncfgs:
            for nip in (ncfg.get('ipv4_address', None), ncfg.get('ipv6_address', None)):
                if nip:
                    nip = nip.split('/', 1)[0]
                    names.add(nip)
    return names

async def handle_request(req, make_response, mimetype):
    global currtz
    global keymap
    global currlocale
    global currtzvintage
    configmanager.check_quorum()
    cfg = configmanager.ConfigManager(None)
    reqpath = req.rel_url.path
    nodename = req.headers.get('CONFLUENT_NODENAME', None)
    clientip = req.headers.get('X-Forwarded-For', None)
    if reqpath == '/self/whoami':
        clientids = env.get('HTTP_CONFLUENT_IDS', None)
        if not clientids:
            rsp = await make_response(mimetype, 400, 'Bad Request')
            await rsp.write( 'Bad Request')
            return
        for ids in clientids.split('/'):
            _, v = ids.split('=', 1)
            repname = disco.get_node_by_uuid_or_mac(v)
            if repname:
                rsp = await make_response(mimetype, 200, 'OK')
                await rsp.write(repname)
                return
        rsp = await make_response(mimetype, 404, 'Unknown')
        return
    if reqpath == '/self/registerapikey':
        crypthmac = env.get('HTTP_CONFLUENT_CRYPTHMAC', None)
        if int(env.get('CONTENT_LENGTH', 65)) > 64:
            rsp = await make_response(mimetype, 400, 'Bad Request')
            await rsp.write('Bad Request')
            return
        cryptkey = await req.read()
        if not (crypthmac and cryptkey):
            rsp = make_response(mimetype, 401, 'Unauthorized')
            await rsp.write('Unauthorized')
            return
        hmackey = cfg.get_node_attributes(nodename, ['secret.selfapiarmtoken'], decrypt=True)
        hmackey = hmackey.get(nodename, {}).get('secret.selfapiarmtoken', {}).get('value', None)
        if not hmackey:
            rsp = await make_response(mimetype, 401, 'Unauthorized')
            await rsp.write('Unauthorized')
            return
        if not isinstance(hmackey, bytes):
            hmackey = hmackey.encode('utf8')
        if not isinstance(cryptkey, bytes):
            cryptkey = cryptkey.encode('utf8')
        try:
            crypthmac = base64.b64decode(crypthmac)
        except Exception:
            rsp = await make_response(mimetype, 400, 'Bad Request')
            await rsp.write('Bad Request')
            return
        righthmac = hmac.new(hmackey, cryptkey, hashlib.sha256).digest()
        if righthmac == crypthmac:
            cfgupdate = {nodename: {'crypted.selfapikey': {'hashvalue': cryptkey}}}
            cfg.set_node_attributes(cfgupdate)
            cfg.clear_node_attributes([nodename], ['secret.selfapiarmtoken'])
            rsp = await make_response(mimetype, 200, 'OK')
            await rsp.write('Accepted')
            return
        rsp = await make_response(mimetype, 401, 'Unauthorized')
        await rsp.write('Unauthorized')
        return
    apikey = req.headers.get('CONFLUENT_APIKEY', None)
    if not (nodename and apikey):
        rsp = await make_response(mimetype, 401, 'Unauthorized')
        await rsp.write('Unauthorized')
        return
    if len(apikey) > 48:
        rsp = await make_response(mimetype, 401, 'Unauthorized')
        await rsp.write('Unauthorized')
        return
    ea = cfg.get_node_attributes(nodename, ['crypted.selfapikey', 'deployment.apiarmed'])
    eak = ea.get(
        nodename, {}).get('crypted.selfapikey', {}).get('hashvalue', None)
    if not eak:
        rsp = await make_response(mimetype, 401, 'Unauthorized')
        await rsp.write(b'Unauthorized')
        return rsp
    if not isinstance(eak, str):
        eak = eak.decode('utf8')
    salt = '$'.join(eak.split('$', 3)[:-1]) + '$'
    if crypt.crypt(apikey, salt) != eak:
        rsp = await make_response(mimetype, 401, 'Unauthorized')
        await rsp.write(b'Unauthorized')
        return
    if ea.get(nodename, {}).get('deployment.apiarmed', {}).get('value', None) == 'once':
        cfg.set_node_attributes({nodename: {'deployment.apiarmed': ''}})
    myip = req.headers.get('X-Forwarded-Host', None)
    if myip and ']' in myip:
        myip = myip.split(']', 1)[0]
    elif myip:
        myip = myip.split(':', 1)[0]
    if myip:
        myip = myip.replace('[', '').replace(']', '')
    retype = req.headers.get('Accept', 'application/yaml')
    isgeneric = False
    if retype == '*/*':
        isgeneric = True
        retype = 'application/yaml'
    if retype == 'application/yaml':
        dumper = yamldump
    elif retype == 'application/json':
        dumper = json.dumps
    else:
        rsp = await make_response(mimetype, 406, 'Not supported')
        await rsp.write(b'Unsupported content type in ACCEPT: ' + retype.encode())
        return
    operation = req.method
    if operation not in ('HEAD', 'GET') and req.content_length > 0:
        reqbody = await req.read()
    if reqpath == '/self/register_discovered':
        rb = json.loads(reqbody)
        if not rb.get('path', None):
            rsp = await make_response(mimetype, 400, 'Bad Requst')
            await rsp.write('Missing Path')
            return
        targurl = '/affluent/systems/by-port/{0}/webaccess'.format(rb['path'])
        tlsverifier = util.TLSCertVerifier(cfg, nodename, 'pubkeys.tls_hardwaremanager')
        wc = webclient.WebConnection(nodename, 443, verifycallback=tlsverifier.verify_cert)
        relaycreds = cfg.get_node_attributes(nodename, 'secret.*', decrypt=True)
        relaycreds = relaycreds.get(nodename, {})
        relayuser = relaycreds.get('secret.hardwaremanagementuser', {}).get('value', None)
        relaypass = relaycreds.get('secret.hardwaremanagementpassword', {}).get('value', None)
        if not relayuser or not relaypass:
            raise Exception('No credentials for {0}'.format(nodename))
        wc.set_basic_credentials(relayuser, relaypass)
        rsp, status = await wc.grab_json_response_with_status(targurl)
        if status == 302:
            newurl = rsp.headers['Location']
            newhost, newport = newurl.replace('https://', '').split('/')[0].split(':')
            def verify_cert(certificate):
                hashval = base64.b64decode(rb['fingerprint'])
                if len(hashval) == 48:
                    return hashlib.sha384(certificate).digest() == hashval
                raise Exception('Certificate validation failed')
            rb['addresses'] = [(newhost, newport)]
            rb['forwarder_url'] = targurl
            rb['forwarder_server'] = nodename
            if 'bay' in rb:
                rb['enclosure.bay'] = rb['bay']
            if rb['type'] == 'lenovo-xcc':
                await ssdp.check_fish(('/DeviceDescription.json', rb), newport, verify_cert)
            elif rb['type'] == 'lenovo-smm2':
                rb['services'] = ['service:lenovo-smm2']
            else:
                rsp = await make_response(mimetype, 400, 'Unsupported Device')
                await rsp.write('Unsupported device for remote discovery registration')
                return
        await disco.detected(rb)
        rsp = await make_response(mimetype, 200, 'OK')
        await rsp.write('Registered')
        return
    if reqpath == '/self/bmcconfig':
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
        bmcaddr = bmcaddr.split('/', 1)[0]
        bmcaddr = await asyncio.get_event_loop().getaddrinfo(bmcaddr, 0)[0]
        bmcaddr = bmcaddr[-1][0]
        if '.' in bmcaddr:  # ipv4 is allowed
            netconfig = netutil.get_nic_config(cfg, nodename, ip=bmcaddr)
            res['bmcipv4'] = bmcaddr
            res['prefixv4'] = netconfig['prefix']
            res['bmcgw'] = netconfig.get('ipv4_gateway', None)
        # credential security results in user/password having to be deferred
        mrsp = await make_response(mimetype, 200, 'OK')
        await mrsp.write(dumper(res))
    elif reqpath == '/self/myattribs':
        cfd = cfg.get_node_attributes(nodename, '*').get(nodename, {})
        rsp = {}
        for k in cfd:
            if k.startswith('secret') or k.startswith('crypt') or 'value' not in cfd[k] or not cfd[k]['value']:
                continue
            rsp[k] = cfd[k]['value']
        mrsp = await make_response(mimetype, 200, 'OK')
        await mrsp.write(dumper(rsp))
    elif reqpath == '/self/netcfg':
        ncfg = netutil.get_full_net_config(cfg, nodename, myip)
        mrsp = await make_response(mimetype, 200, 'OK')
        await mrsp.write(dumper(ncfg))
    elif reqpath in ('/self/deploycfg', '/self/deploycfg2'):
        if 'CONFLUENT_MGTIFACE' in req.headers:
            nicname = req.headers['CONFLUENT_MGTIFACE']
            try:
                ifidx = int(nicname)
            except ValueError:
                with open('/sys/class/net/{}/ifindex'.format(nicname), 'r') as nici:
                    ifidx = int(nici.read())
            ncfg = netutil.get_nic_config(cfg, nodename, ifidx=ifidx)
        else:
            ncfg = netutil.get_nic_config(cfg, nodename, serverip=myip)
        if reqpath == '/self/deploycfg':
            for key in list(ncfg):
                if 'v6' in key:
                    del ncfg[key]
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
        ncfg['confluent_uuid'] = configmanager.get_global('confluent_uuid')
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
            needlocalectl = True
            try:
                with open('/etc/vconsole.conf') as consconf:
                    for line in consconf.read().split('\n'):
                        line = line.split('#', 1)[0]
                        if '=' not in line:
                            continue
                        k, v = line.split('=', 1)
                        if k == 'KEYMAP':
                            keymap = v.replace('"', '')
                            needlocalectl = False
                if not needlocalectl:
                    needlocalectl = True
                    localeconf = None
                    if os.path.exists('/etc/locale.conf'):
                        localeconf = '/etc/locale.conf'
                    elif os.path.exists('/etc/default/locale'):
                        localeconf = '/etc/default/locale'
                    if localeconf:
                        with open(localeconf) as lcin:
                            for line in lcin.read().split('\n'):
                                line = line.split('#', 1)[0]
                                if '=' not in line:
                                    continue
                                k, v = line.split('=', 1)
                                if k == 'LANG':
                                    needlocalectl = False
                                    currlocale = v.replace('"', '')
            except IOError:
                pass
            if needlocalectl:
                try:
                    langinfo = util.run(['localectl', 'status'])[0].split(b'\n')
                except Exception:
                    langinfo = []
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
            try:
                tdcout, tdcerr = await util.check_output('timedatectl')
                tdc = tdcout.split(b'\n')
            except subprocess.CalledProcessError:
                tdc = []
                currtzvintage = time.time()
                ncfg['timezone'] = currtz
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
        mrsp = await make_response(mimetype, 200, 'OK')
        await mrsp.write(dumper(ncfg).encode())
        return mrsp
    elif reqpath == '/self/sshcert' and reqbody:
        if not sshutil.ca_exists():
            mrsp = await make_response(mimetype, 500, 'Unconfigured')
            await msrp.write(b'CA is not configured on this system (run ...)')
            return mrsp
        pals = get_extra_names(nodename, cfg, myip)
        cert = sshutil.sign_host_key(reqbody, nodename, pals)
        mrsp = await make_response('text/plain', 200, 'OK')
        await mrsp.write(cert)
    elif reqpath == '/self/nodelist':
        nodes, _ = get_cluster_list(nodename, cfg)
        if isgeneric:
            mrsp = await make_response('text/plain', 200, 'OK')
            for node in util.natural_sort(nodes):
                await mrsp.write(node + '\n')
        else:
            mrsp = await make_response(retype, 200, 'OK')
            if retype == 'application/yaml':
                await mrsp.write(listdump(list(util.natural_sort(nodes))))
            else:
                await mrsp.write(dumper(list(util.natural_sort(nodes))))
    elif reqpath == '/self/remoteconfigbmc' and reqbody:
        try:
            reqbody = yamlload(reqbody)
        except Exception:
            reqbody = None
        cfgmod = reqbody.get('configmod', 'unspecified')
        if cfgmod == 'xcc':
            xcc.remote_nodecfg(nodename, cfg)
        elif cfgmod == 'tsm':
            tsm.remote_nodecfg(nodename, cfg)
        else:
            mrsp = await make_response(mimetype, 500, 'unsupported configmod')
            await mrsp.write('Unsupported configmod "{}"'.format(cfgmod))
        mrsp = await make_response(mimetype, 200, 'Ok')
        await mrsp.write('complete')
    elif reqpath == '/self/updatestatus' and reqbody:
        update = yamlload(reqbody)
        statusstr = update.get('state', None)
        statusdetail = update.get('state_detail', None)
        didstateupdate = False
        if statusstr:
            cfg.set_node_attributes({nodename: {'deployment.state': statusstr}})
            didstateupdate = True
        if statusdetail:
            cfg.set_node_attributes({nodename: {'deployment.state_detail': statusdetail}})
            didstateupdate = True
        if 'status' not in update and didstateupdate:
            mrsp = await make_response(mimetype, 200, 'Ok')
            await mrsp.write('Accepted')
            return
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
            mrsp = await make_response('text/plain', 200, 'OK')
            await mrsp.write('OK')
        else:
            mrsp = await make_response('text/plain', 500, 'Error')
            await mrsp.write('No pending profile detected, unable to accept status update')
    elif reqpath == '/self/saveapikey' and reqbody:
        if not isinstance(reqbody, str):
            reqbody = reqbody.decode('utf8')
        cfg.set_node_attributes({
            nodename: {'deployment.sealedapikey': {'value': reqbody}}})
        mrsp = await make_response(mimetype, 200, 'OK')
    elif reqpath.startswith('/self/remoteconfig/') and 'POST' == operation:
        scriptcat = reqpath.replace('/self/remoteconfig/', '')
        playlist = []
        for privacy in ('public', 'private'):
            slist, profile = get_scriptlist(
                scriptcat, cfg, nodename,
                '/var/lib/confluent/{0}/os/{{0}}/ansible/{{1}}'.format(privacy))
            dirname = '/var/lib/confluent/{2}/os/{0}/ansible/{1}/'.format(
                profile, scriptcat, privacy)
            if not os.path.isdir(dirname):
                dirname = '/var/lib/confluent/{2}/os/{0}/ansible/{1}.d/'.format(
                    profile, scriptcat, privacy)
            for filename in slist:
                if filename.endswith('.yaml') or filename.endswith('.yml'):
                    playlist.append(os.path.join(dirname, filename))
        if playlist:
            runansible.run_playbooks(playlist, [nodename])
            mrsp = await make_response(mimetype, 202, 'Queued')
        else:
            mrsp = await make_response(mimetype, 200, 'OK')
            return
    elif reqpath.startswith('/self/remotesyncfiles'):
        if 'POST' == operation:
            pals = get_extra_names(nodename, cfg, myip)
            result = syncfiles.start_syncfiles(
                nodename, cfg, json.loads(reqbody), pals)
            mrsp = await make_response(mimetype, result[0])
            await mrsp.write(result[1])
            return
        if 'GET' == operation:
            status, output = syncfiles.get_syncresult(nodename)
            output = json.dumps(output)
            mrsp = await make_response('application/json', status)
            await mrsp.write(output)
            return
    elif reqpath.startswith('/self/remoteconfig/status'):
        rst = runansible.running_status.get(nodename, None)
        if not rst:
            mrsp = await make_response(mimetype, 204, 'Not Running')
            return
        mrsp = await make_response(mimetype, 200, 'OK')
        if rst.complete:
            del runansible.running_status[nodename]
        await mrsp.write(rst.dump_text())
        return
    elif reqpath.startswith('/self/scriptlist/'):
        scriptcat = reqpath.replace('/self/scriptlist/', '')
        slist, _ = get_scriptlist(
            scriptcat, cfg, nodename,
            '/var/lib/confluent/public/os/{0}/scripts/{1}')
        if slist:
            mrsp = await make_response('application/yaml', 200, 'OK')
            await mrsp.write(yamldump(util.natural_sort(slist)))
        else:
            mrsp = await make_response(mimetype, 200, 'OK')
    elif reqpath.startswith('/self/profileprivate/pending/'):
        fname = reqpath.replace('/self/profileprivate/', '')
        deployinfo = cfg.get_node_attributes(
        nodename, ('deployment.*',))
        deployinfo = deployinfo.get(nodename, {})
        profile = deployinfo.get(
            'deployment.pendingprofile', {}).get('value', '')
        if not profile:
            mrsp = await make_response(mimetype, 400, 'No pending profile')
            await mrsp.write('No profile')
            return
        fname = '/var/lib/confluent/private/os/{}/{}'.format(profile, fname)
        try:
            with open(fname, 'rb') as privdata:
                mrsp = await make_response(200, 'OK')
                await mrsp.write(privdata.read())
                return
        except IOError:
            mrsp = await make_response(mimetype, 404, 'Not Found')
            await mrsp.write('Not found')
            return
    else:
        mrsp = await make_response(mimetype, 404, 'Not Found')
        await mrsp.write('Not found')

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
        slist = list(util.natural_sort(os.listdir(target)))
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
