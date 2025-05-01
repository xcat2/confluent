
import codecs
import confluent.util as util
import confluent.messages as msg
import eventlet
import json
import struct
webclient = eventlet.import_patched('pyghmi.util.webclient')
import eventlet.green.socket as socket
import eventlet.green.ssl as ssl
import eventlet
import confluent.interface.console as conapi
import io


class RetainedIO(io.BytesIO):
    # Need to retain buffer after close
    def __init__(self):
        self.resultbuffer = None
    def close(self):
        self.resultbuffer = self.getbuffer()
        super().close()

def fixuuid(baduuid):
    # VMWare changes the endian stuff in BIOS
    uuidprefix = (baduuid[:8], baduuid[9:13], baduuid[14:18])
    a = codecs.encode(struct.pack('<IHH', *[int(x, 16) for x in uuidprefix]),
        'hex')
    a = util.stringify(a)
    uuid = (a[:8], a[8:12], a[12:16], baduuid[19:23], baduuid[24:])
    return '-'.join(uuid).lower()

class VmConsole(conapi.Console):
    def __init__(self, host, port, tls, configmanager=None):
        self.tls = tls
        self.host = host
        self.port = port
        self.socket = None
        self.nodeconfig = configmanager

    def connect(self, callback):
        try:
            self.socket = socket.create_connection((self.host, self.port))
        except Exception:
            callback(conapi.ConsoleEvent.Disconnect)
        if self.tls:
            if not self.nodeconfig:
                raise Exception('config manager instance required for TLS operation')
            kv = util.TLSCertVerifier(
                self.nodeconfig, self.host, 'pubkeys.tls').verify_cert
            sock = ssl.wrap_socket(self.socket, cert_reqs=ssl.CERT_NONE)
            # The above is supersedeed by the _certverify, which provides
            # known-hosts style cert validaiton
            bincert = sock.getpeercert(binary_form=True)
            if not kv(bincert):
                raise pygexc.UnrecognizedCertificate('Unknown certificate', bincert)
            self.socket = sock
        self.connected = True
        self.datacallback = callback
        self.recvr = eventlet.spawn(self.recvdata)

    def write(self, data):
        self.socket.sendall(data)

    def close(self):
        self.connected = False
        if self.socket:
            self.socket.close()

    def recvdata(self):
        while self.connected:
            try:
                pendingdata = self.socket.recv(1024)
            except Exception as e:
                pendingdata = b''
            if pendingdata == b'':
                self.connected = False
                self.datacallback(conapi.ConsoleEvent.Disconnect)
                return
            reply = b''
            while pendingdata and pendingdata[0] == 255:
                cmd = pendingdata[1]
                if cmd == 255:
                    pendingdata = pendingdata[1:]
                    break
                subcmd = pendingdata[2]
                if cmd == 253:  # DO
                    # binary, suppress go ohaed
                    if subcmd in (0, 3):
                        reply += b'\xff\xfb' + bytes([subcmd])  # will
                    else:
                        reply += b'\xff\xfc' + bytes([subcmd]) # won't do anything else
                    pendingdata = pendingdata[3:]
                elif cmd == 251:  # will
                    # binary, suppress go ahead, echo
                    if subcmd in (0, 1, 3):
                        reply += b'\xff\xfd' + bytes([subcmd])  # do the implemented things
                    else:
                        reply += B'\xff\xfe' + bytes([subcmd])  # don't do others'
                    pendingdata = pendingdata[3:]
                else:
                    raise Exception(repr(pendingdata[:3]))
            if reply:
                self.write(reply)
            if pendingdata:
                self.datacallback(pendingdata)



class VmwApiClient:
    def __init__(self, vcsa, user, password, configmanager):
        self.cachedurls = {}
        self.user = user
        self.password = password
        if configmanager:
            cv = util.TLSCertVerifier(
                configmanager, vcsa, 'pubkeys.tls_hardwaremanager'
            ).verify_cert
        else:
            cv = lambda x: True

        try:
            self.user = self.user.decode()
            self.password = self.password.decode()
        except Exception:
            pass
        self.wc = webclient.SecureHTTPConnection(vcsa, port=443, verifycallback=cv)
        self.login()
        self.vmlist = {}
        self.vmbyid = {}

    def login(self):
        self.wc.set_basic_credentials(self.user, self.password)
        self.wc.request('POST', '/api/session')
        rsp = self.wc.getresponse()
        body = rsp.read().decode().replace('"', '')
        del self.wc.stdheaders['Authorization']
        self.wc.set_header('vmware-api-session-id', body)

    def get_screenshot(self, vm, outfile):
        vm = self.index_vm(vm)
        url = f'/screen?id={vm}'
        wc = self.wc.dupe()
        wc.set_basic_credentials(self.user, self.password)
        fd = webclient.FileDownloader(wc, url, outfile)
        fd.start()
        fd.join()

    def list_vms(self):
        rsp = self.wc.grab_json_response('/api/vcenter/vm')
        self.vmlist = {}
        for vm in rsp:
            name = vm['name']
            vmid = vm['vm']
            self.vmlist[name] = vmid
            self.vmbyid[vmid] = name
        return self.vmlist

    def index_vm(self, vm):
        if vm in self.vmlist:
            return self.vmlist[vm]
        if vm in self.vmbyid:
            return vm
        self.list_vms()
        if vm not in self.vmlist:
            if vm in self.vmbyid:
                return vm
            raise Exception("VM not found")
        return self.vmlist[vm]

    def get_vm(self, vm):
        vm = self.index_vm(vm)
        rsp = self.wc.grab_json_response(f'/api/vcenter/vm/{vm}')
        return rsp

    def get_vm_inventory(self, vm):
        rawinv = self.get_vm(vm)
        hwver = rawinv['hardware']['version']
        uuid = fixuuid(rawinv['identity']['bios_uuid'])
        serial = rawinv['identity']['instance_uuid']
        invitems = []
        sysinfo = {'name': 'System',
                   'present': True,
                   'information': {
                       'Product name': 'VMWare Virtual machine',
                       'UUID': uuid,
                       'Manufacturer': 'VMWare',
                       'Model': hwver,
                       'Serial Number': serial
                  }}
        inventory = [sysinfo]
        for nic in rawinv['nics']:
            nicinfo = rawinv['nics'][nic]
            label = nicinfo['label']
            mac = nicinfo['mac_address']
            inventory.append({
                'present': True,
                'name': label,
                'information': {
                'Type': 'Ethernet',
                'Model': nicinfo['type'],
                'MAC Address 1': mac}
                })
        yield msg.KeyValueData({'inventory': inventory}, vm)




    def get_vm_host(self, vm):
        # unfortunately, the REST api doesn't manifest this as a simple attribute,
        vm = self.index_vm(vm)
        rsp = self.wc.grab_json_response(f'/api/vcenter/host')
        for hostinfo in rsp:
            host = hostinfo['host']
            rsp = self.wc.grab_json_response(f'/api/vcenter/vm?hosts={host}')
            for guest in rsp:
                if guest['vm'] == vm:
                    return hostinfo

    def get_vm_serial(self, vm):
        vm = self.index_vm(vm)
        rsp = self.wc.grab_json_response_with_status(f'/api/vcenter/vm/{vm}/hardware/serial')
        if rsp[1] == 200 and len(rsp[0]) > 0:
            portid = rsp[0][0]['port']
            rsp = self.wc.grab_json_response_with_status(f'/api/vcenter/vm/{vm}/hardware/serial/{portid}')
            if rsp[1] == 200:
                if rsp[0]['backing']['type'] != 'NETWORK_SERVER':
                    return
                netloc = rsp[0]['backing']['network_location']
                portnum = netloc.split(':')[-1]
                tlsenabled = False
                if netloc.startswith('telnets'):
                    tlsenabled = True
                hostinfo = self.get_vm_host(vm)
                hostname = hostinfo['name']
                rsp[0]
                return {
                    'server': hostname,
                    'port': portnum,
                    'tls': tlsenabled,
                    }

    def get_vm_bootdev(self, vm):
        vm = self.index_vm(vm)
        rsp = self.wc.grab_json_response_with_status(f'/api/vcenter/vm/{vm}/hardware/boot')
        if rsp[0]['enter_setup_mode']:
            return 'setup'
        rsp = self.wc.grab_json_response_with_status(f'/api/vcenter/vm/{vm}/hardware/boot/device')
        try:
            if rsp[0][0]['type'] == 'ETHERNET':
                return 'network'
        except IndexError:
            pass
        return 'default'

    def get_vm_power(self, vm):
        vm = self.index_vm(vm)
        rsp = self.wc.grab_json_response(f'/api/vcenter/vm/{vm}/power')
        if rsp['state'] == 'POWERED_ON':
            return 'on'
        if rsp['state'] == 'POWERED_OFF':
            return 'off'
        if rsp['state'] == 'SUSPENDED':
            return 'suspended'
        raise Exception("Unknown response {}".format(repr(rsp)))

    def set_vm_power(self, vm, state):
        current = None
        targstate = state
        vm = self.index_vm(vm)
        if state == 'boot':
            current = self.get_vm_power(vm)
            if current == 'on':
                state = 'reset'
                targstate = state
            else:
                targstate = 'on'
                state = 'start'
        elif state == 'on':
            state = 'start'
        elif state == 'off':
            state = 'stop'
        rsp = self.wc.grab_json_response_with_status(f'/api/vcenter/vm/{vm}/power?action={state}', method='POST')
        return targstate, current


    def set_vm_bootdev(self, vm, bootdev):
        vm = self.index_vm(vm)
        self.wc.set_header('Content-Type', 'application/json')
        try:
            bootdevs = []
            entersetup = False
            if bootdev == 'setup':
                entersetup = True
            elif bootdev == 'default':
                # In theory, we should be able to send an empty device list.
                # However, vmware api counter to documentation seems to just ignore
                # such a request. So instead we just go "disk first"
                # and rely upon fast fail/retry to take us to a normal place
                currdisks, rcode = self.wc.grab_json_response_with_status(f'/api/vcenter/vm/{vm}/hardware/disk')
                currdisks = [x['disk'] for x in currdisks]
                bootdevs.append({'type': 'DISK', 'disks': currdisks})
            elif bootdev in ('net', 'network'):
                currnics, rcode = self.wc.grab_json_response_with_status(f'/api/vcenter/vm/{vm}/hardware/ethernet')
                for nic in currnics:
                    bootdevs.append({'type': 'ETHERNET', 'nic': nic['nic']})
            payload = {'devices': bootdevs}
            rsp = self.wc.grab_json_response_with_status(f'/api/vcenter/vm/{vm}/hardware/boot/device',
                                                        payload,
                                                        method='PUT')
            rsp = self.wc.grab_json_response_with_status(f'/api/vcenter/vm/{vm}/hardware/boot',
                                                        {'enter_setup_mode': entersetup},
                                                        method='PATCH')
        finally:
            del self.wc.stdheaders['Content-Type']


def prep_vcsa_clients(nodes, configmanager):
    cfginfo = configmanager.get_node_attributes(nodes, ['hardwaremanagement.manager', 'secret.hardwaremanagementuser', 'secret.hardwaremanagementpassword'], decrypt=True)
    clientsbyvcsa = {}
    clientsbynode = {}
    for node in nodes:
        cfg = cfginfo[node]
        currvcsa = cfg['hardwaremanagement.manager']['value']
        if currvcsa not in clientsbyvcsa:
             user = cfg.get('secret.hardwaremanagementuser', {}).get('value', None)
             passwd = cfg.get('secret.hardwaremanagementpassword', {}).get('value', None)
             clientsbyvcsa[currvcsa] = VmwApiClient(currvcsa, user, passwd, configmanager)
        clientsbynode[node] = clientsbyvcsa[currvcsa]
    return clientsbynode

def retrieve(nodes, element, configmanager, inputdata):
    clientsbynode = prep_vcsa_clients(nodes, configmanager)
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
    clientsbynode = prep_vcsa_clients(nodes, configmanager)
    for node in nodes:
        currclient = clientsbynode[node]
        if element == ['power', 'state']:
            newstate, oldstate = currclient.set_vm_power(node, inputdata.powerstate(node))
            yield  msg.PowerState(node, newstate, oldstate)
        elif element == ['boot', 'nextdevice']:
            currclient.set_vm_bootdev(node, inputdata.bootdevice(node))
            yield msg.BootDevice(node, currclient.get_vm_bootdev(node))

# assume this is only console for now
def create(nodes, element, configmanager, inputdata):
    clientsbynode = prep_vcsa_clients(nodes, configmanager)
    for node in nodes:
        serialdata = clientsbynode[node].get_vm_serial(node)
        return VmConsole(serialdata['server'], serialdata['port'], serialdata['tls'], configmanager)



if __name__ == '__main__':
    import sys
    import os
    from pprint import pprint
    myuser = os.environ['VMWUSER']
    mypass = os.environ['VMWPASS']
    vc = VmwApiClient(sys.argv[1], myuser, mypass, None)
    vm = sys.argv[2]
    if sys.argv[3] == 'setboot':
        vc.set_vm_bootdev(vm, sys.argv[4])
        vc.get_vm_bootdev(vm)
    elif sys.argv[3] == 'power':
        vc.set_vm_power(vm, sys.argv[4])
    elif sys.argv[3] == 'getinfo':
        vc.get_vm(vm)
        print("Bootdev: " + vc.get_vm_bootdev(vm))
        print("Power: " + vc.get_vm_power(vm))
        print("Serial: " + repr(vc.get_vm_serial(vm)))
