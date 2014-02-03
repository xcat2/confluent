import collections
import confluent.exceptions as exc
import confluent.interface.console as conapi
import confluent.messages as msg
import eventlet
import eventlet.event
import eventlet.greenpool as greenpool
import eventlet.queue
import os
import pyghmi.exceptions as pygexc
import pyghmi.ipmi.console as console
import pyghmi.ipmi.command as ipmicommand
console.session.select = eventlet.green.select
console.session.threading = eventlet.green.threading

tmptimeout = None
_ipmithread = None

def _ipmi_evtloop():
    global tmptimeout
    while (1):
        try:
            if tmptimeout is not None:
                console.session.Session.wait_for_rsp(timeout=tmptimeout)
                tmptimeout = None
            else:
                console.session.Session.wait_for_rsp(timeout=600)
        except:
            import traceback
            traceback.print_exc()


def get_conn_params(node, configdata):
    if 'secret.ipmiuser' in configdata:
        username = configdata['secret.ipmiuser']['value']
    elif 'secret.managementuser' in configdata:
        username = configdata['secret.managementuser']['value']
    else:
        username = 'USERID'
    if 'secret.ipmipassphrase' in configdata:
        passphrase = configdata['secret.ipmipassphrase']['value']
    elif 'secret.managementpassphrase' in configdata:
        passphrase = configdata['secret.managementpassphrase']['value']
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
            ['secret.ipmiuser', 'secret.ipmipassphrase',
             'secret.managementuser', 'secret.managementpassphrase',
             'hardwaremanagement.manager'])
        connparams = get_conn_params(node, configdata[node])
        self.username = connparams['username']
        self.password = connparams['passphrase']
        self.kg = connparams['kg']
        self.bmc = connparams['bmc']
        self.port = connparams['port']
        # Cannot actually create console until 'connect', when we get callback

    def handle_data(self, data):
        if type(data) == dict:
            disconnect = frozenset(('Session Disconnected', 'timeout'))
            if 'error' in data and data['error'] in disconnect:
                self.broken = True
                self.datacallback(conapi.ConsoleEvent.Disconnect)
            else:
                raise Exception("Unrecognized pyghmi input %s" % repr(data))
        else:
            self.datacallback(data)

    def connect(self,callback):
        global _ipmithread
        self.datacallback = callback
        self.solconnection=console.Console(bmc=self.bmc, port=self.port,
                                           userid=self.username,
                                           password=self.password, kg=self.kg,
                                           force=True,
                                           iohandler=self.handle_data)
        if _ipmithread is None:
            _ipmithread = eventlet.spawn(_ipmi_evtloop)

    def write(self, data):
        self.solconnection.send_data(data)

    def wait_for_data(self, timeout=600):
        """Wait for some network event.

        This is currently not guaranteed to actually have data when
        return.  This is supposed to be something more appropriate
        than sleep(0), but only marginally so.
        """
        # reason for this is that we currently nicely pass through the callback
        # straight to ipmi library.  To implement this accurately, easiest path
        # would be to add a layer through the callback.  IMO there isn't enough
        # value in assuring data coming back to bother with making the stack
        # taller than it has to be
        #TODO: a channel for the ipmithread to tug back instead of busy wait
        #while tmptimeout is not None:
        #    eventlet.sleep(0)
        console.session.Session.wait_for_rsp(timeout=timeout)


class IpmiIterator(object):
    def __init__(self, operator, nodes, element, cfg, inputdata):
        crypt = cfg.decrypt
        cfg.decrypt = True
        configdata = cfg.get_node_attributes(nodes,
            ['secret.ipmiuser', 'secret.ipmipassphrase',
             'secret.managementuser', 'secret.managementpassphrase',
             'hardwaremanagement.manager'])
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
    def __iter__():
        return self

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
        self.inputdata = inputdata
        self.ipmicmd = ipmicommand.Command(bmc=connparams['bmc'],
                                           userid=connparams['username'],
                                           password=connparams['passphrase'],
                                           kg=connparams['kg'],
                                           port=connparams['port'],
                                           onlogon=self.logged)
        print "spin on logon"
        while not (self.loggedin or self.broken):
            print "on"
            console.session.Session.wait_for_rsp(timeout=600)
        print "hmph..."

    def logged(self, response, ipmicmd):
        print "huzzah"
        if 'error' in response:
            self.broken = True
            self.error = response['error']
        else:
            self.loggedin = True

    def handle_request(self):
        bootdevices = {
            'optical': 'cd'
        }
        while not (self.loggedin or self.broken):
            console.session.Session.wait_for_rsp(timeout=600)
        if self.broken:
            if self.error == 'timeout':
                raise exc.TargetEndpointTimeout()
            else:
                raise Exception(self.error)
        if self.element == [ 'power', 'state' ]:
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
        elif self.element == [ 'boot', 'device' ]:
            if 'read' == self.op:
                bootdev = self.ipmicmd.get_bootdev()
                if bootdev['bootdev'] in bootdevices:
                    bootdev['bootdev'] = bootdevices[bootdev['bootdev']]
                return msg.BootDevice(node=self.node,
                        device=bootdev['bootdev'])
            elif 'update' == self.op:
                bootdev = self.inputdata.bootdevice(self.node)
                bootdev = self.ipmicmd.set_bootdev(bootdev)
                if bootdev['bootdev'] in bootdevices:
                    bootdev['bootdev'] = bootdevices[bootdev['bootdev']]
                return msg.BootDevice(node=self.node,
                        device=bootdev['bootdev'])



def create(nodes, element, configmanager, inputdata):
    if element == [ '_console', 'session' ]:
        if len(nodes) > 1:
            raise Exception("_console/session does not support multiple nodes")
        return IpmiConsole(nodes[0], configmanager)
    else:
        return IpmiIterator('update', nodes, element, configmanager, inputdata)

def update(nodes, element, configmanager, inputdata):
    return create(nodes, element, configmanager, inputdata)



def retrieve(nodes, element, configmanager, inputdata):
    return IpmiIterator('read', nodes, element, configmanager, inputdata)

