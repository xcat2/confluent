import collections
import eventlet
import eventlet.event
import os
import pyghmi.ipmi.console as console
console.session.select = eventlet.green.select

_ipmithread = None
#pullchain is a pipe to tug on to induce the ipmi thread process pending data
pullchain = None
chainpulled = False
tmptimeout = None
ipmiq = collections.deque([])
ipmiwaiters = collections.deque([])


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
    global chainpulled
    os.read(intline,1)  # answer the bell
    chainpulled = False
    while ipmiq:
        cval = ipmiq.popleft()
        if hasattr(cval[0], '__call__'):
            cval[0](*cval[1])



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
        self.solconnection = console.Console(bmc=self.bmc,
                                             port=self.port,
                                             userid=self.username,
                                             password=self.password,
                                             kg=self.kg,
                                             force=True,
                                             iohandler=callback)
        if _ipmithread is None:
            pullchain = os.pipe()
            _ipmithread = eventlet.spawn(_ipmi_evtloop)

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
        waitevt = eventlet.event.Event()
        ipmiwaiters.append(waitevt)
        waitevt.wait()
        #TODO: a channel for the ipmithread to tug back instead of busy wait
        #while tmptimeout is not None:
        #    eventlet.sleep(0)
        #console.session.Session.wait_for_rsp(timeout=timeout)


def create(nodes, element, configmanager):
    if element == '_console/session':
        if len(nodes) > 1:
            raise Exception("_console/session does not support multiple nodes")
        return Console(nodes[0], configmanager)
    else:
        raise Exception(
            "TODO(jbjohnso): ipmi api implementation of %s" % element)


def retrieve(nodes, element, configmanager):
    raise Exception("TODO(jbjohnso): ipmi get implementation of %s" % element)
