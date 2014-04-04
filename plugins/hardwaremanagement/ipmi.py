import collections
import confluent.exceptions as exc
import confluent.interface.console as conapi
import confluent.messages as msg
import eventlet
import eventlet.event
import eventlet.green.threading as threading
import eventlet.greenpool as greenpool
import eventlet.queue
import os
import pyghmi.exceptions as pygexc
import pyghmi.ipmi.console as console
import pyghmi.ipmi.command as ipmicommand
import socket
console.session.select = eventlet.green.select
console.session.threading = eventlet.green.threading

_ipmithread = None
_ipmiwaiters = []

def _ipmi_evtloop():
    while True:
        try:
            console.session.Session.wait_for_rsp(timeout=600)
            while _ipmiwaiters:
                waiter = _ipmiwaiters.pop()
                waiter.send()
        except:
            import traceback
            traceback.print_exc()


def get_conn_params(node, configdata):
    if 'secret.hardwaremanagementuser' in configdata:
        username = configdata['secret.hardwaremanagementuser']['value']
    else:
        username = 'USERID'
    if 'secret.hardwaremanagementpassphrase' in configdata:
        passphrase = configdata['secret.hardwaremanagementpassphrase']['value']
    else:
        passphrase = 'PASSW0RD' # for lack of a better guess
    if 'hardwaremanagement.manager' in configdata:
        bmc = configdata['hardwaremanagement.manager']['value']
    else:
        bmc = node
    if 'secret.ipmikg' in configdata:
        kg = configdata['secret.ipmikg']['value']
    else:
        kg = passphrase
    #TODO(jbjohnso): check if the end has some number after a : without []
    #for non default port
    return {
        'username': username,
        'passphrase': passphrase,
        'kg': kg,
        'bmc': bmc,
        'port': 623,
    }


class IpmiConsole(conapi.Console):
    def __init__(self, node, config):
        crypt = config.decrypt
        config.decrypt = True
        self.broken = False
        configdata = config.get_node_attributes([node],
            ['secret.hardwaremanagementuser',
             'secret.hardwaremanagementpassphrase',
             'secret.ipmikg', 'hardwaremanagement.manager'])
        connparams = get_conn_params(node, configdata[node])
        config.decrypt = crypt
        self.username = connparams['username']
        self.password = connparams['passphrase']
        self.kg = connparams['kg']
        self.bmc = connparams['bmc']
        self.port = connparams['port']
        self.connected = False
        # Cannot actually create console until 'connect', when we get callback

    def handle_data(self, data):
        if type(data) == dict:
            disconnect = frozenset(('Session Disconnected', 'timeout'))
            if 'error' in data and data['error'] in disconnect:
                self.broken = True
                self.error = data['error']
                if self.connected:
                    self.datacallback(conapi.ConsoleEvent.Disconnect)
            else:
                raise Exception("Unrecognized pyghmi input %s" % repr(data))
        else:
            self.datacallback(data)

    def connect(self,callback):
        self.datacallback = callback
        try:
            self.solconnection = console.Console(bmc=self.bmc, port=self.port,
                                                userid=self.username,
                                                password=self.password,
                                                kg=self.kg, force=True,
                                                iohandler=self.handle_data)
            while not self.solconnection.connected and not self.broken:
                w = eventlet.event.Event()
                _ipmiwaiters.append(w)
                w.wait()
            if self.broken:
                raise exc.TargetEndpointUnreachable(self.error)
        except socket.gaierror as err:
            raise exc.TargetEndpointUnreachable(str(err))


    def write(self, data):
        self.solconnection.send_data(data)


class IpmiIterator(object):
    def __init__(self, operator, nodes, element, cfg, inputdata):
        crypt = cfg.decrypt
        cfg.decrypt = True
        configdata = cfg.get_node_attributes(nodes,
            ['secret.hardwaremanagementuser',
             'secret.hardwaremanagementpassphrase',
             'secret.ipmikg', 'hardwaremanagement.manager'])
        cfg.decrypt = crypt
        self.gpile = greenpool.GreenPile()
        for node in nodes:
            self.gpile.spawn(perform_request, operator, node, element, configdata, inputdata)

    def __iter__(self):
        return self

    def next(self):
        ndata = self.gpile.next()
        # need to apply any translations between pyghmi and confluent
        return ndata


def perform_request(operator, node, element, configdata, inputdata):
    return IpmiHandler(operator, node, element, configdata, inputdata).handle_request()


class IpmiHandler(object):
    def __init__(self, operation, node, element, cfd, inputdata):
        self.broken = False
        eventlet.sleep(0)
        self.cfg = cfd[node]
        self.loggedin = False
        self.node = node
        self.element = element
        self.op = operation
        connparams = get_conn_params(node, self.cfg)
        self.ipmicmd = None
        self._logevt = threading.Event()
        self.inputdata = inputdata
        self.ipmicmd = ipmicommand.Command(bmc=connparams['bmc'],
                                           userid=connparams['username'],
                                           password=connparams['passphrase'],
                                           kg=connparams['kg'],
                                           port=connparams['port'],
                                           onlogon=self.logged)

    bootdevices = {
        'optical': 'cd'
    }

    def logged(self, response, ipmicmd):
        if 'error' in response:
            self.broken = True
            self.error = response['error']
        else:
            self.loggedin = True
        self._logevt.set()

    def handle_request(self):
        self._logevt.wait()
        if self.broken:
            if self.error == 'timeout':
                raise exc.TargetEndpointUnreachable('Target timed out')
            else:
                raise Exception(self.error)
        if self.element == [ 'power', 'state' ]:
            return self.power()
        elif self.element == [ 'boot', 'nextdevice' ]:
            return self.bootdevice()

    def bootdevice(self):
        if 'read' == self.op:
            bootdev = self.ipmicmd.get_bootdev()
            if bootdev['bootdev'] in self.bootdevices:
                bootdev['bootdev'] = self.bootdevices[bootdev['bootdev']]
            return msg.BootDevice(node=self.node,
                    device=bootdev['bootdev'])
        elif 'update' == self.op:
            bootdev = self.inputdata.bootdevice(self.node)
            bootdev = self.ipmicmd.set_bootdev(bootdev)
            if bootdev['bootdev'] in self.bootdevices:
                bootdev['bootdev'] = self.bootdevices[bootdev['bootdev']]
            return msg.BootDevice(node=self.node,
                    device=bootdev['bootdev'])

    def power(self):
        if 'read' == self.op:
            power = self.ipmicmd.get_power()
            return msg.PowerState(node=self.node,
                                  state=power['powerstate'])
        elif 'update' == self.op:
            powerstate = self.inputdata.powerstate(self.node)
            #TODO: call with wait argument
            self.ipmicmd.set_power(powerstate)
            power = self.ipmicmd.get_power()
            return msg.PowerState(node=self.node,
                                  state=power['powerstate'])



def initthread():
    global _ipmithread
    if _ipmithread is None:
        _ipmithread = eventlet.spawn(_ipmi_evtloop)


def create(nodes, element, configmanager, inputdata):
    initthread()
    if element == [ '_console', 'session' ]:
        if len(nodes) > 1:
            raise Exception("_console/session does not support multiple nodes")
        return IpmiConsole(nodes[0], configmanager)
    else:
        return IpmiIterator('update', nodes, element, configmanager, inputdata)

def update(nodes, element, configmanager, inputdata):
    initthread()
    return create(nodes, element, configmanager, inputdata)



def retrieve(nodes, element, configmanager, inputdata):
    initthread()
    return IpmiIterator('read', nodes, element, configmanager, inputdata)

