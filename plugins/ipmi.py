import eventlet
import pyghmi.ipmi.console as console
console.session.select = eventlet.green.select

_loopthread = None


def _ipmi_evtloop():
    while (1):
        console.session.Session.wait_for_rsp(timeout=600)


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
        global _loopthread
        self.solconnection = console.Console(bmc=self.bmc,
                                             port=self.port,
                                             userid=self.username,
                                             password=self.password,
                                             kg=self.kg,
                                             iohandler=callback)
        if _loopthread is None:
            _loopthread = eventlet.spawn(_ipmi_evtloop)

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
        console.session.Session.wait_for_rsp(timeout=timeout)


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
