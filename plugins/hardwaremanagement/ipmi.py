import collections
import confluent.exceptions as exc
import confluent.interface.console as conapi
import confluent.messages as msg
import eventlet
import eventlet.event
import eventlet.greenpool as greenpool
import eventlet.queue
import os
import pyghmi.ipmi.console as console
import pyghmi.ipmi.command as ipmicommand
console.session.select = eventlet.green.select

_ipmithread = None
#pullchain is a pipe to tug on to induce the ipmi thread process pending data
pullchain = None
chainpulled = False
tmptimeout = None
ipmiq = collections.deque([])
ipmiwaiters = collections.deque([])


def wait_on_ipmi():
    waitevt = eventlet.event.Event()
    ipmiwaiters.append(waitevt)
    waitevt.wait()


def _ipmi_evtloop():
    global tmptimeout
    global pullchain
    console.session.Session.register_handle_callback(pullchain[0],
                                                     _process_chgs)
    while (1):
        try:
            if tmptimeout is not None:
                console.session.Session.wait_for_rsp(timeout=tmptimeout)
                tmptimeout = None
            else:
                console.session.Session.wait_for_rsp(timeout=600)
            while ipmiwaiters:
                waiter = ipmiwaiters.popleft()
                waiter.send()
        except RuntimeError:
            raise
        except:
            import traceback
            traceback.print_exc()

def _process_chgs(intline):
    #here we receive functions to run in our thread
    #the tuples on the deque consist of:
    #function, arg tuple, and optionally a callback
    #to send the return value back to the requester
    global chainpulled
    os.read(intline,1)  # answer the bell
    chainpulled = False
    try:
        while ipmiq:
            cval = ipmiq.popleft()
            if hasattr(cval[0], '__call__'):
                if isinstance(cval[1], tuple):
                    rv = cval[0](*cval[1])
                elif isinstance(cval[1], dict):
                    rv = cval[0](**cval[1])
                if len(cval) > 2:
                    cval[2](rv)
    except:  # assure the thread does not crash and burn
        import traceback
        traceback.print_exc()
    # If we are inside a loop within pyghmi, this is our only shot
    # so we have to wake up anything that might be interested in
    # state changes here as well as the evtloop
    while ipmiwaiters:
        waiter = ipmiwaiters.popleft()
        waiter.send()


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
        global pullchain
        global chainpulled
        self.datacallback = callback
        if _ipmithread is None:
            pullchain = os.pipe()
            _ipmithread = eventlet.spawn(_ipmi_evtloop)
        self.solconnection = None
        ipmiq.append((console.Console,{'bmc': self.bmc,
                                      'port': self.port,
                                      'userid': self.username,
                                      'password': self.password,
                                      'kg': self.kg,
                                      'force': True,
                                      'iohandler': self.handle_data}, self.got_consobject))
        if not chainpulled:
            chainpulled = True
            os.write(pullchain[1],'1')
        while self.solconnection is None:
            wait_on_ipmi()

    def got_consobject(self, solconnection):
        self.solconnection = solconnection

    def write(self, data):
        global chainpulled
        while self.solconnection is None and not self.broken:
            wait_on_ipmi()
        ipmiq.append((self.solconnection.send_data, (data,)))
        if not chainpulled:
            chainpulled = True
            os.write(pullchain[1],'1')

        #self.solconnection.send_data(data)

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
        global tmptimeout
        global chainpulled
        tmptimeout = timeout
        if not chainpulled:
            chainpulled=True
            os.write(pullchain[1],'1')
        eventlet.sleep(0.001)
        wait_on_ipmi()
        #TODO: a channel for the ipmithread to tug back instead of busy wait
        #while tmptimeout is not None:
        #    eventlet.sleep(0)
        #console.session.Session.wait_for_rsp(timeout=timeout)


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
        global chainpulled
        global _ipmithread
        global pullchain
        self.broken = False
        if _ipmithread is None:
            pullchain = os.pipe()
            _ipmithread = eventlet.spawn(_ipmi_evtloop)
        eventlet.sleep(0)
        self.cfg = cfd[node]
        self.loggedin = False
        self.node = node
        self.element = element
        self.op = operation
        connparams = get_conn_params(node, self.cfg)
        self.ipmicmd = None
        self.inputdata = inputdata
        ipmiq.append((ipmicommand.Command,{'bmc': connparams['bmc'],
                                           'userid': connparams['username'],
                                           'password': connparams['passphrase'],
                                           'kg': connparams['kg'],
                                           'port': connparams['port'],
                                           'onlogon': self.logged},
                                           self.got_ipmicmd))
        if not chainpulled:
            chainpulled = True
            os.write(pullchain[1],'1')
        while self.ipmicmd == None:
            wait_on_ipmi()

    def got_ipmicmd(self, ipmicmd):
        self.ipmicmd = ipmicmd

    def logged(self, response, ipmicmd):
        if 'error' in response:
            self.broken = True
            self.error = response['error']
        else:
            self.loggedin = True

    def call_ipmicmd(self, function, *args):
        global chainpulled
        self.lastrsp = None
        ipmiq.append((function, args, self.got_rsp))
        if not chainpulled:
            chainpulled = True
            os.write(pullchain[1],'1')
        while self.lastrsp is None:
            wait_on_ipmi()
        return self.lastrsp

    def got_rsp(self, response):
        self.lastrsp = response

    def handle_request(self):
        bootdevices = {
            'optical': 'cd'
        }
        while not (self.loggedin or self.broken):
            wait_on_ipmi()
        if self.broken:
            if self.error == 'timeout':
                raise exc.TargetEndpointTimeout()
            else:
                raise Exception(self.error)
        if self.element == [ 'power', 'state' ]:
            if 'read' == self.op:
                power = self.call_ipmicmd(self.ipmicmd.get_power)
                return msg.PowerState(node=self.node,
                                      state=power['powerstate'])
            elif 'update' == self.op:
                powerstate = self.inputdata.powerstate(self.node)
                #TODO: call with wait argument
                self.call_ipmicmd(self.ipmicmd.set_power, powerstate)
                power = self.call_ipmicmd(self.ipmicmd.get_power)
                return msg.PowerState(node=self.node,
                                      state=power['powerstate'])
        elif self.element == [ 'boot', 'device' ]:
            if 'read' == self.op:
                bootdev = self.call_ipmicmd(self.ipmicmd.get_bootdev)
                if bootdev['bootdev'] in bootdevices:
                    bootdev['bootdev'] = bootdevices[bootdev['bootdev']]
                return msg.BootDevice(node=self.node,
                        device=bootdev['bootdev'])
            elif 'update' == self.op:
                bootdev = self.inputdata.bootdevice(self.node)
                bootdev = self.call_ipmicmd(self.ipmicmd.set_bootdev, bootdev)
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

