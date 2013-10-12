import collections
import eventlet
import eventlet.event
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
ipmisessions = {}


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
        if tmptimeout is not None:
            console.session.Session.wait_for_rsp(timeout=tmptimeout)
            tmptimeout = None
        else:
            console.session.Session.wait_for_rsp(timeout=600)
        while ipmiwaiters:
            waiter = ipmiwaiters.popleft()
            waiter.send()

def _process_chgs(intline):
    #here we receive functions to run in our thread
    #the tuples on the deque consist of:
    #function, arg tuple, and optionally a callback
    #to send the return value back to the requester
    global chainpulled
    os.read(intline,1)  # answer the bell
    chainpulled = False
    while ipmiq:
        cval = ipmiq.popleft()
        if hasattr(cval[0], '__call__'):
            if isinstance(cval[1], tuple):
                rv = cval[0](*cval[1])
            elif isinstance(cval[1], dict):
                rv = cval[0](**cval[1])
            if len(cval) > 2:
                cval[2](rv)



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


class Console(object):
    def __init__(self, node, config):
        crypt = config.decrypt
        config.decrypt = True
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

    def connect(self,callback):
        global _ipmithread
        global pullchain
        global ipmisessions
        global chainpulled
        try:
            ipmisession = ipmisessions[(self.bmc, self.port)]
        except KeyError:
            ipmisession = None
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
                                      'ipmisession': ipmisession,
                                      'iohandler': callback}, self.got_consobject))
        if not chainpulled:
            chainpulled = True
            os.write(pullchain[1],'1')
        while self.solconnection is None:
            wait_on_ipmi()
        if ipmisession is None:
            ipmisessions[(self.bmc, self.port)] = \
                    self.solconnection.ipmi_session

    def got_consobject(self, solconnection):
        self.solconnection = solconnection

    def write(self, data):
        global chainpulled
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
    def __init__(self, operator, nodes, element, cfg):
        configdata = cfg.get_node_attributes(nodes,
            ['secret.ipmiuser', 'secret.ipmipassphrase',
             'secret.managementuser', 'secret.managementpassphrase',
             'hardwaremanagement.manager'])
        for node in nodes:
            IpmiHandler(operator, node, element, configdata)

    def __iter__(self):
        return self

    def next(self):
        pass
        




class IpmiHandler(object):
    def __iter__():
        return self

    def __init__(self, operation, node, element, cfd):
        self.cfg = cfd[node]
        self.node = node
        self.element = element
        self.op = operation
        connparams = get_conn_params(node, self.cfg)
        self.ipmicmd = None
        try:
            ipmisession = ipmisessions[(self.bmc, self.port)]
        except KeyError:
            ipmisession = None
        ipmiq.append((ipmicommand.Command,{'bmc': connparams['bmc'],
                                           'userid': connparams['username'],
                                           'password': connparams['passphrase'],
                                           'kg': connparams['kg'],
                                           'port': connparams['port'],
                                           'onlogon': self.handle_request,
                                           'ipmisession': ipmisession},
                                           got_ipmicmd))
        while self.ipmicmd == None:
            wait_on_ipmi()
        if ipmisession is None:
            ipmisessions[(self.bmc, self.port)] = self.ipmicmd.ipmi_session

    def got_ipmicmd(self, ipmicmd):
        self.ipmicmd = ipmicmd

    def call_ipmicmd(self, function, *args):
        self.lastrsp = None
        ipmiq.append((function, args, self.got_rsp))
        while self.lastrsp is None:
            wait_on_ipmi()
        return self.lastrsp

    def got_rsp(self, response):
        self.lastrsp = response

    def handle_request(self, response):
        if 'error' in response:
            raise Exception(response['error'])
        if self.element == 'power/state':
            if 'read' == self.op:
                rsp = self.call_ipmi(self.ipmicmd.get_power)
                print(rsp)

def create(nodes, element, configmanager):
    if element == '_console/session':
        if len(nodes) > 1:
            raise Exception("_console/session does not support multiple nodes")
        return Console(nodes[0], configmanager)
    else:
        raise Exception(
            "TODO(jbjohnso): ipmi api implementation of %s" % element)



def retrieve(nodes, element, configmanager):
    pass
