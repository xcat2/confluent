
import asyncio
import confluent.vinzmanager as vinzmanager
import confluent.util as util
import confluent.messages as msg
import confluent.tasks as tasks
import aiohmi.util.webclient as webclient
import aiohmi.exceptions as pygexc
import confluent.interface.console as conapi
import io
import urllib.parse as urlparse
import aiohttp

class CustomVerifier(aiohttp.Fingerprint):
    def __init__(self, verifycallback):
        self._certverify = verifycallback

    def check(self, transport):
        sslobj = transport.get_extra_info("ssl_object")
        cert = sslobj.getpeercert(binary_form=True)
        if not self._certverify(cert):
            transport.close()
            raise pygexc.UnrecognizedCertificate('Unknown certificate',
                                                 cert)


class RetainedIO(io.BytesIO):
    # Need to retain buffer after close
    def __init__(self):
        self.resultbuffer = None
    def close(self):
        self.resultbuffer = self.getbuffer()
        super().close()

class KvmConnection:
    def __init__(self, consdata):
        #self.ws = WrappedWebSocket(host=bmc)
        #self.ws.set_verify_callback(kv)
        ticket = consdata['ticket']
        user = consdata['user']
        port = consdata['port']
        urlticket = urlparse.quote(ticket)
        host = consdata['host']
        guest = consdata['guest']
        pac = consdata['pac']  # fortunately, we terminate this on our end, but it does kind of reduce the value of the
        # 'ticket' approach, as the general cookie must be provided as cookie along with the VNC ticket
        hosturl = host
        if ':' in hosturl:
            hosturl = '[' + hosturl + ']'
        self.url = f'/api2/json/nodes/{host}/{guest}/vncwebsocket?port={port}&vncticket={urlticket}'
        self.fprint = consdata['fprint']
        self.cookies = {
            'PVEAuthCookie': pac,
            }
        self.protos = ['binary']
        self.host = host
        self.portnum = 8006
        self.password = consdata['ticket']


class KvmConnHandler:
    def __init__(self, pmxclient, node):
        self.pmxclient = pmxclient
        self.node = node

    async def connect(self):
        consdata = await self.pmxclient.get_vm_ikvm(self.node)
        consdata['fprint'] = self.pmxclient.fprint
        return KvmConnection(consdata)

class PmxConsole(conapi.Console):
    def __init__(self, consdata, node, configmanager, apiclient):
        self.ws = None
        self.clisess = None
        self.consdata = consdata
        self.nodeconfig = configmanager
        self.connected = False
        self.bmc = consdata['server']
        self.node = node
        self.recvr = None
        self.apiclient = apiclient

    async def recvdata(self):
        try:
            while self.connected:
                pendingdata = await self.ws.receive()
                if pendingdata.type == aiohttp.WSMsgType.BINARY:
                    await self.datacallback(pendingdata.data)
                    continue
                elif pendingdata.type == aiohttp.WSMsgType.TEXT:
                    await self.datacallback(pendingdata.data.encode())
                    continue
                elif pendingdata.type == aiohttp.WSMsgType.CLOSE:
                    await self.datacallback(conapi.ConsoleEvent.Disconnect)
                    return
                else:
                    print("Unknown response in PmxConsole WSHandler")
        except asyncio.CancelledError:
            pass

    async def connect(self, callback):
        if await self.apiclient.get_vm_power(self.node) != 'on':
            await callback(conapi.ConsoleEvent.Disconnect)
            return
        # socket = new WebSocket(socketURL, 'binary'); - subprotocol binary
        # client handshake is:
        #     socket.send(PVE.UserName + ':' + ticket + "\n");

        # Peer sends 'OK' on handshake, other than that it's direct pass through
        # send '2' every 30 seconds for keepalive
        # data is xmitted with 0:<len>:data
        # resize is sent with 1:columns:rows:""
        self.datacallback = callback
        kv = util.TLSCertVerifier(
            self.nodeconfig, self.node, 'pubkeys.tls_hardwaremanager').verify_cert
        bmc = self.bmc
        if '%' in self.bmc:
            prefix = self.bmc.split('%')[0]
            bmc = prefix + ']'
        self.ssl = CustomVerifier(kv)
        ticket = self.consdata['ticket']
        user = self.consdata['user']
        port = self.consdata['port']
        urlticket = urlparse.quote(ticket)
        host = self.consdata['host']
        guest = self.consdata['guest']
        pac = self.consdata['pac']  # fortunately, we terminate this on our end, but it does kind of reduce the value of the
        # 'ticket' approach, as the general cookie must be provided as cookie along with the VNC ticket
        cookies = aiohttp.CookieJar(unsafe=True, quote_cookie=False)
        cookies.update_cookies({'PVEAuthCookie': pac})
        self.clisess = aiohttp.ClientSession(cookie_jar=cookies)
        self.ws = await self.clisess.ws_connect(
            f'wss://{self.bmc}:8006/api2/json/nodes/{host}/{guest}/vncwebsocket?port={port}&vncticket={urlticket}',
            protocols=['binary'], ssl=self.ssl)
        await self.ws.send_str(f'{user}:{ticket}\n')
        data = await self.ws.receive()
        if data.data == b'OK' or data.data == 'OK':
            await self.ws.receive()  # swallow the 'starting serial terminal' message
            self.connected = True
            self.recvr = tasks.spawn_task(self.recvdata())
        else:
            print(repr(data.data))
        return

    async def write(self, data):
        try:
            dlen = str(len(data))
            data = data.decode()
            await self.ws.send_str('0:' + dlen + ':' + data)
        except Exception:
            await self.datacallback(conapi.ConsoleEvent.Disconnect)

    async def close(self):
        if self.recvr:
            self.recvr.cancel()
            self.recvr = None
        if self.ws:
            await self.ws.close()
        if self.clisess:
            await self.clisess.close()
        self.connected = False
        self.datacallback = None

class PmxApiClient:
    def __init__(self, server, user, password, configmanager):
        self.user = user
        self.password = password
        self.pac = None
        if configmanager:
            cv = util.TLSCertVerifier(
                configmanager, server, 'pubkeys.tls'
            ).verify_cert
        else:
            cv = lambda x: True

        try:
            self.user = self.user.decode()
            self.password = self.password.decode()
        except Exception:
            pass
        self.server = server
        self.wc = webclient.WebConnection(server, port=8006, verifycallback=cv)
        self.fprint = configmanager.get_node_attributes(server, 'pubkeys.tls').get(server, {}).get('pubkeys.tls', {}).get('value', None)
        self.vmmap = {}
        self.vmlist = {}
        self.vmbyid = {}
        self.logged = False

    async def login(self):
        loginform = {
                'username': self.user,
                'password': self.password,
            }
        loginbody = urlparse.urlencode(loginform)
        rsp = await self.wc.grab_json_response_with_status('/api2/json/access/ticket', loginbody, headers={'Content-Type': 'application/x-www-form-urlencoded'})
        self.pac = rsp[0]['data']['ticket']
        self.wc.cookies.update_cookies({'PVEAuthCookie': self.pac})
        self.wc.set_header('CSRFPreventionToken', rsp[0]['data']['CSRFPreventionToken'])
        self.logged = True


    def get_screenshot(self, vm, outfile):
        raise Exception("Not implemented")

    async def map_vms(self):
        if not self.logged:
            await self.login()
        rsp = await self.wc.grab_json_response('/api2/json/cluster/resources')
        for datum in rsp.get('data', []):
            if datum['type'] == 'qemu':
                self.vmmap[datum['name']] = (datum['node'], datum['id'])
        return self.vmmap


    async def get_vm(self, vm):
        if vm not in self.vmmap:
            await self.map_vms()
        return self.vmmap[vm]


    async def get_vm_inventory(self, vm):
        host, guest = await self.get_vm(vm)
        cfg = await self.wc.grab_json_response(f'/api2/json/nodes/{host}/{guest}/pending')
        myuuid = None
        sysinfo = {'name': 'System', 'present': True, 'information': {
            'Product name': 'Proxmox qemu virtual machine',
            'Manufacturer': 'qemu'
            }}
        invitems = [sysinfo]
        for datum in cfg['data']:
            if datum['key'] == 'smbios1':
                smbios = datum['value']
                for smbio in smbios.split(','):
                    if '=' in smbio:
                        k, v = smbio.split('=')
                        if k == 'uuid':
                            sysinfo['information']['UUID'] = v
            elif datum['key'].startswith('net'):
                label = 'Network adapter {}'.format(datum['key'])
                niccfg = datum['value']
                cfgparts = niccfg.split(',')
                nicmodel, mac = cfgparts[0].split('=')
                invitems.append({
                    'present': True,
                    'name': label,
                    'information': {
                        'Type': 'Ethernet',
                        'Model': nicmodel,
                        'MAC Address 1': mac,
                        }
                    })
        yield msg.KeyValueData({'inventory': invitems}, vm)


    async def get_vm_ikvm(self, vm):
        return await self.get_vm_consproxy(vm, 'vnc')

    async def get_vm_serial(self, vm):
        return await self.get_vm_consproxy(vm, 'term')

    async def get_vm_consproxy(self, vm, constype):
        host, guest = await self.get_vm(vm)
        rsp = await self.wc.grab_json_response_with_status(f'/api2/json/nodes/{host}/{guest}/{constype}proxy', method='POST')
        consdata = rsp[0]['data']
        consdata['server'] = self.server
        consdata['host'] = host
        consdata['guest'] = guest
        consdata['pac'] = self.pac
        return consdata

    async def get_vm_bootdev(self, vm):
        host, guest = await self.get_vm(vm)
        cfg = await self.wc.grab_json_response(f'/api2/json/nodes/{host}/{guest}/pending')
        for datum in cfg['data']:
            if datum['key'] == 'boot':
                bootseq = datum.get('pending', datum['value'])
                for kv in bootseq.split(','):
                    k, v = kv.split('=')
                    if k == 'order':
                        bootdev = v.split(';')[0]
                        if bootdev.startswith('net'):
                            return 'network'
        return 'default'


    async def get_vm_power(self, vm):
        host, guest = await self.get_vm(vm)
        rsp = await self.wc.grab_json_response(f'/api2/json/nodes/{host}/{guest}/status/current')
        rsp = rsp['data']
        currstatus = rsp["qmpstatus"] # stopped, "running"
        if currstatus == 'running':
            return 'on'
        elif currstatus == 'stopped':
            return 'off'
        raise Exception("Unknnown response to status query")

    async def set_vm_power(self, vm, state):
        host, guest = await self.get_vm(vm)
        current = None
        newstate = ''
        targstate = state
        if targstate == 'boot':
            targstate = 'on'
        if state == 'boot':
            current = await self.get_vm_power(vm)
            if current == 'on':
                state = 'reset'
                newstate = 'reset'
            else:
                state = 'start'
        elif state == 'on':
            state = 'start'
        elif state == 'off':
            state = 'stop'
        if state == 'reset': # check for pending config
            cfg = await self.wc.grab_json_response(f'/api2/json/nodes/{host}/{guest}/pending')
            for datum in cfg['data']:
                if datum['key'] == 'boot' and 'pending' in datum:
                    await self.set_vm_power(vm, 'off')
                    await self.set_vm_power(vm, 'on')
                    state = ''
                    newstate = 'reset'
        if state:
            rsp = await self.wc.grab_json_response_with_status(f'/api2/json/nodes/{host}/{guest}/status/{state}', method='POST')
        if state and state != 'reset':
            newstate = await self.get_vm_power(vm)
            while newstate != targstate:
                await asyncio.sleep(0.1)
                newstate = await self.get_vm_power(vm)
        return newstate, current

    async def set_vm_bootdev(self, vm, bootdev):
        host, guest = await self.get_vm(vm)
        if bootdev not in ('net', 'network', 'default'):
            raise Exception('Requested boot device not supported')
        cfg = await self.wc.grab_json_response(f'/api2/json/nodes/{host}/{guest}/pending')
        nonnetdevs = []
        netdevs = []
        for datum in cfg['data']:
            if datum['key'] == 'boot':
                bootseq = datum.get('pending', datum['value'])
                for item in bootseq.split(','):
                    if item.startswith('order='):
                        bootdevs = item.replace('order=', '').split(';')
                        for cbootdev in bootdevs:
                            if cbootdev.startswith('net'):
                                netdevs.append(cbootdev)
                            else:
                                nonnetdevs.append(cbootdev)
                if bootdev in ('net', 'network'):
                    newbootdevs = netdevs + nonnetdevs
                else:
                    newbootdevs = nonnetdevs + netdevs
                neworder = 'order=' + ';'.join(newbootdevs)
        self.wc.set_header('Content-Type', 'application/json')
        try:
            await self.wc.grab_json_response_with_status(f'/api2/json/nodes/{host}/{guest}/config', {'boot': neworder}, method='PUT')
        finally:
            del self.wc.stdheaders['Content-Type']


def prep_proxmox_clients(nodes, configmanager):
    cfginfo = configmanager.get_node_attributes(nodes, ['hardwaremanagement.manager', 'secret.hardwaremanagementuser', 'secret.hardwaremanagementpassword'], decrypt=True)
    clientsbypmx = {}
    clientsbynode = {}
    for node in nodes:
        cfg = cfginfo[node]
        currpmx = cfg['hardwaremanagement.manager']['value']
        if currpmx not in clientsbypmx:
             user = cfg.get('secret.hardwaremanagementuser', {}).get('value', None)
             passwd = cfg.get('secret.hardwaremanagementpassword', {}).get('value', None)
             clientsbypmx[currpmx] = PmxApiClient(currpmx, user, passwd, configmanager)
        clientsbynode[node] = clientsbypmx[currpmx]
    return clientsbynode

async def retrieve(nodes, element, configmanager, inputdata):
    clientsbynode = prep_proxmox_clients(nodes, configmanager)
    for node in nodes:
        currclient = clientsbynode[node]
        if element == ['power', 'state']:
            yield msg.PowerState(node, await currclient.get_vm_power(node))
        elif element == ['boot', 'nextdevice']:
            yield msg.BootDevice(node, await currclient.get_vm_bootdev(node))
        elif element[:2] == ['inventory', 'hardware'] and len(element) == 4:
            async for rsp in currclient.get_vm_inventory(node):
                yield rsp
        elif element == ['console', 'ikvm_methods']:
            dsc = {'ikvm_methods': ['vnc']}
            yield msg.KeyValueData(dsc, node)
        elif element == ['console', 'ikvm_screenshot']:
            # good background for the webui, and kitty
            yield msg.ConfluentNodeError(node, "vnc available, screenshot not available")

async def update(nodes, element, configmanager, inputdata):
    clientsbynode = prep_proxmox_clients(nodes, configmanager)
    for node in nodes:
        currclient = clientsbynode[node]
        if element == ['power', 'state']:
            newstate, oldstate = await currclient.set_vm_power(node, inputdata.powerstate(node))
            yield  msg.PowerState(node, newstate, oldstate)
        elif element == ['boot', 'nextdevice']:
            await currclient.set_vm_bootdev(node, inputdata.bootdevice(node))
            yield msg.BootDevice(node, await currclient.get_vm_bootdev(node))
        elif element == ['console', 'ikvm']:
            try:
                currclient = clientsbynode[node]
                url = await vinzmanager.get_url(node, inputdata, nodeparmcallback=KvmConnHandler(currclient, node).connect)
            except Exception as e:
                print(repr(e))
                return
            yield msg.ChildCollection(url)
            return

# assume this is only console for now
async def create(nodes, element, configmanager, inputdata):
    clientsbynode = prep_proxmox_clients(nodes, configmanager)
    for node in nodes:
        if element == ['console', 'ikvm']:
            try:
                currclient = clientsbynode[node]
                url = await vinzmanager.get_url(node, inputdata, nodeparmcallback=KvmConnHandler(currclient, node).connect)
            except Exception as e:
                print(repr(e))
                return
            yield msg.ChildCollection(url)
            return
        serialdata = await clientsbynode[node].get_vm_serial(node)
        yield PmxConsole(serialdata, node, configmanager, clientsbynode[node])
        return


if __name__ == '__main__':
    import sys
    import os
    from pprint import pprint
    myuser = os.environ['PMXUSER']
    mypass = os.environ['PMXPASS']
    vc = PmxApiClient(sys.argv[1], myuser, mypass, None)
    vm = sys.argv[2]
    if sys.argv[3] == 'setboot':
        vc.set_vm_bootdev(vm, sys.argv[4])
        vc.get_vm_bootdev(vm)
    elif sys.argv[3] == 'power':
        vc.set_vm_power(vm, sys.argv[4])
    elif sys.argv[3] == 'getinfo':
        print(repr(list(vc.get_vm_inventory(vm))))
        print("Bootdev: " + vc.get_vm_bootdev(vm))
        print("Power: " + vc.get_vm_power(vm))
        #print("Serial: " + repr(vc.get_vm_serial(vm)))
