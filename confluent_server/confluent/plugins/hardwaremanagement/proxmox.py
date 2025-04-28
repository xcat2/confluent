
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

class RetainedIO(io.BytesIO):
    # Need to retain buffer after close
    def __init__(self):
        self.resultbuffer = None
    def close(self):
        self.resultbuffer = self.getbuffer()
        super().close()

class PmxConsole(conapi.Console):
    pass
    # this more closely resembles OpenBMC.., websocket based and all

class PmxApiClient:
    def __init__(self, server, user, password, configmanager):
        self.user = user
        self.password = password
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
        #wss:///api2/json/nodes/{host}/{guest}/vncwebsocket?port=5900&vncticket=URLENCODEDTICKET
        raise Exception('TODO')

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
            return off
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
        print(repr(rsp))

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
    clientsbynode = prep_vcsa_clients(nodes, configmanager)
    for node in nodes:
        serialdata = clientsbynode[node].get_vm_serial(node)
        return VmConsole(serialdata['server'], serialdata['port'], serialdata['tls'])



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
