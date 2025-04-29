
import codecs
import confluent.util as util
import confluent.messages as msg
import eventlet
import json
import struct
webclient = eventlet.import_patched('pyghmi.util.webclient')
import eventlet.green.socket as socket
import eventlet
import confluent.interface.console as conapi
import io
import urllib.parse as urlparse
import eventlet.green.ssl as ssl


try:
    websocket = eventlet.import_patched('websocket')
    wso = websocket.WebSocket
except Exception:
    wso = object

class RetainedIO(io.BytesIO):
    # Need to retain buffer after close
    def __init__(self):
        self.resultbuffer = None
    def close(self):
        self.resultbuffer = self.getbuffer()
        super().close()

class WrappedWebSocket(wso):

    def set_verify_callback(self, callback):
        self._certverify = callback

    def connect(self, url, **options):

        add_tls = url.startswith('wss://')
        if add_tls:
            hostname, port, resource, _ = websocket._url.parse_url(url)
            if hostname[0] != '[' and ':' in hostname:
                hostname = '[{0}]'.format(hostname)
            if resource[0] != '/':
                resource = '/{0}'.format(resource)
            url = 'ws://{0}:8006{1}'.format(hostname,resource)
        else:
            return super(WrappedWebSocket, self).connect(url, **options)
        self.sock_opt.timeout = options.get('timeout', self.sock_opt.timeout)
        self.sock, addrs = websocket._http.connect(url, self.sock_opt, websocket._http.proxy_info(**options),
                                           options.pop('socket', None))
        self.sock = ssl.wrap_socket(self.sock, cert_reqs=ssl.CERT_NONE)
        # The above is supersedeed by the _certverify, which provides
        # known-hosts style cert validaiton
        bincert = self.sock.getpeercert(binary_form=True)
        if not self._certverify(bincert):
            raise pygexc.UnrecognizedCertificate('Unknown certificate', bincert)
        try:
            try:
                self.handshake_response = websocket._handshake.handshake(self.sock, *addrs, **options)
            except TypeError:
                self.handshake_response = websocket._handshake.handshake(self.sock, url, *addrs, **options)
            if self.handshake_response.status in websocket._handshake.SUPPORTED_REDIRECT_STATUSES:
                options['redirect_limit'] = options.pop('redirect_limit', 3) - 1
                if options['redirect_limit'] < 0:
                     raise Exception('Redirect limit hit')
                url = self.handshake_response.headers['location']
                self.sock.close()
                return self.connect(url, **options)
            self.connected = True
        except:
            if self.sock:
                self.sock.close()
                self.sock = None
            raise


class PmxConsole(conapi.Console):
    def __init__(self, consdata, node, configmanager, apiclient):
        self.ws = None
        self.consdata = consdata
        self.nodeconfig = configmanager
        self.connected = False
        self.bmc = consdata['server']
        self.node = node
        self.recvr = None
        self.apiclient = apiclient

    def recvdata(self):
        while self.connected:
            try:
                pendingdata = self.ws.recv()
            except websocket.WebSocketConnectionClosedException:
                pendingdata = ''
            if pendingdata == '':
                self.datacallback(conapi.ConsoleEvent.Disconnect)
                return
            self.datacallback(pendingdata)

    def connect(self, callback):
        if self.apiclient.get_vm_power(self.node) != 'on':
            callback(conapi.ConsoleEvent.Disconnect)
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
        self.ws = WrappedWebSocket(host=bmc)
        self.ws.set_verify_callback(kv)
        ticket = self.consdata['ticket']
        user = self.consdata['user']
        port = self.consdata['port']
        urlticket = urlparse.quote(ticket)
        host = self.consdata['host']
        guest = self.consdata['guest']
        pac = self.consdata['pac']  # fortunately, we terminate this on our end, but it does kind of reduce the value of the
        # 'ticket' approach, as the general cookie must be provided as cookie along with the VNC ticket
        self.ws.connect(f'wss://{self.bmc}:8006/api2/json/nodes/{host}/{guest}/vncwebsocket?port={port}&vncticket={urlticket}',
                        host=bmc, cookie=f'PVEAuthCookie={pac}', # cookie='XSRF-TOKEN={0}; SESSION={1}'.format(wc.cookies['XSRF-TOKEN'], wc.cookies['SESSION']),
                        subprotocols=['binary'])
        self.ws.send(f'{user}:{ticket}\n')
        data = self.ws.recv()
        if data == b'OK':
            self.ws.recv()  # swallow the 'starting serial terminal' message
            self.connected = True
            self.recvr = eventlet.spawn(self.recvdata)
        else:
            print(repr(data))
        return

    def write(self, data):
        try:
            dlen = str(len(data))
            data = data.decode()
            self.ws.send('0:' + dlen + ':' + data)
        except websocket.WebSocketConnectionClosedException:
            self.datacallback(conapi.ConsoleEvent.Disconnect)

    def close(self):
        if self.recvr:
            self.recvr.kill()
            self.recvr = None
        if self.ws:
            self.ws.close()
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
        self.wc = webclient.SecureHTTPConnection(server, port=8006, verifycallback=cv)
        self.vmmap = {}
        self.login()
        self.vmlist = {}
        self.vmbyid = {}

    def login(self):
        loginform = {
                'username': self.user,
                'password': self.password,
            }
        loginbody = urlparse.urlencode(loginform)
        rsp = self.wc.grab_json_response_with_status('/api2/json/access/ticket', loginbody)
        self.wc.cookies['PVEAuthCookie'] = rsp[0]['data']['ticket']
        self.pac = rsp[0]['data']['ticket']
        self.wc.set_header('CSRFPreventionToken', rsp[0]['data']['CSRFPreventionToken'])


    def get_screenshot(self, vm, outfile):
        raise Exception("Not implemented")

    def map_vms(self):
        rsp = self.wc.grab_json_response('/api2/json/cluster/resources')
        for datum in rsp.get('data', []):
            if datum['type'] == 'qemu':
                self.vmmap[datum['name']] = (datum['node'], datum['id'])
        return self.vmmap


    def get_vm(self, vm):
        if vm not in self.vmmap:
            self.map_vms()
        return self.vmmap[vm]


    def get_vm_inventory(self, vm):
        host, guest = self.get_vm(vm)
        cfg = self.wc.grab_json_response(f'/api2/json/nodes/{host}/{guest}/pending')
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


    def get_vm_serial(self, vm):
        # This would be termproxy
        # Example url
        host, guest = self.get_vm(vm)
        rsp = self.wc.grab_json_response_with_status(f'/api2/json/nodes/{host}/{guest}/termproxy', method='POST')
        consdata = rsp[0]['data']
        consdata['server'] = self.server
        consdata['host'] = host
        consdata['guest'] = guest
        consdata['pac'] = self.pac
        return consdata

    def get_vm_bootdev(self, vm):
        host, guest = self.get_vm(vm)
        cfg = self.wc.grab_json_response(f'/api2/json/nodes/{host}/{guest}/pending')
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


    def get_vm_power(self, vm):
        host, guest = self.get_vm(vm)
        rsp = self.wc.grab_json_response(f'/api2/json/nodes/{host}/{guest}/status/current')
        rsp = rsp['data']
        currstatus = rsp["qmpstatus"] # stopped, "running"
        if currstatus == 'running':
            return 'on'
        elif currstatus == 'stopped':
            return 'off'
        raise Exception("Unknnown response to status query")

    def set_vm_power(self, vm, state):
        host, guest = self.get_vm(vm)
        if state == 'boot':
            current = self.get_vm_power(vm)
            if current == 'on':
                state = 'reset'
            else:
                state = 'start'
        elif state == 'on':
            state = 'start'
        elif state == 'off':
            state = 'stop'
        rsp = self.wc.grab_json_response_with_status(f'/api2/json/nodes/{host}/{guest}/status/{state}', method='POST')

    def set_vm_bootdev(self, vm, bootdev):
        host, guest = self.get_vm(vm)
        if bootdev not in ('net', 'network', 'default'):
            raise Exception('Requested boot device not supported')
        cfg = self.wc.grab_json_response(f'/api2/json/nodes/{host}/{guest}/pending')
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
            self.wc.grab_json_response_with_status(f'/api2/json/nodes/{host}/{guest}/config', {'boot': neworder}, method='PUT')
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

def retrieve(nodes, element, configmanager, inputdata):
    clientsbynode = prep_proxmox_clients(nodes, configmanager)
    for node in nodes:
        currclient = clientsbynode[node]
        if element == ['power', 'state']:
            yield msg.PowerState(node, currclient.get_vm_power(node))
        elif element == ['boot', 'nextdevice']:
            yield msg.BootDevice(node, currclient.get_vm_bootdev(node))
        elif element[:2] == ['inventory', 'hardware'] and len(element) == 4:
            for rsp in currclient.get_vm_inventory(node):
                yield rsp
        elif element == ['console', 'ikvm_methods']:
            dsc = {'ikvm_methods': ['screenshot']}
            yield msg.KeyValueData(dsc, node)
        elif element == ['console', 'ikvm_screenshot']:
            # good background for the webui, and kitty
            imgdata = RetainedIO()
            imgformat = currclient.get_screenshot(node, imgdata)
            imgdata = imgdata.getvalue()
            if imgdata:
                yield msg.ScreenShot(imgdata, node, imgformat=imgformat)






def update(nodes, element, configmanager, inputdata):
    clientsbynode = prep_proxmox_clients(nodes, configmanager)
    for node in nodes:
        currclient = clientsbynode[node]
        if element == ['power', 'state']:
            currclient.set_vm_power(node, inputdata.powerstate(node))
            yield  msg.PowerState(node, currclient.get_vm_power(node))
        elif element == ['boot', 'nextdevice']:
            currclient.set_vm_bootdev(node, inputdata.bootdevice(node))
            yield msg.BootDevice(node, currclient.get_vm_bootdev(node))

# assume this is only console for now
def create(nodes, element, configmanager, inputdata):
    clientsbynode = prep_proxmox_clients(nodes, configmanager)
    for node in nodes:
        serialdata = clientsbynode[node].get_vm_serial(node)
        return PmxConsole(serialdata, node, configmanager, clientsbynode[node])



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
