import eventlet
console = eventlet.import_patched('pyghmi.ipmi.console')
ipmisession = eventlet.import_patched('pyghmi.ipmi.private.session')

_loopthread = None


def _ipmi_evtloop():
    while (1):
        ipmisession.Session.wait_for_rsp(timeout=600)


def get_conn_params(node, config):
    if 'secret.ipmiuser' in configdata:
        username = configdata['secret.ipmiuser']['value']
    elif 'secret.managementuser' in configdata:
        username = configdata['secret.managementuser']['value']
    else:
        username = 'USERID'
    if 'secret.ipmipassphrase' in configdata:
        passphrase = configddata['secret.ipmi.passphrase']['value']
    elif 'secret.managementpassphrase' in configdata:
        passphrase = configdata['secret.managementpassphrase']
    else:
        passphrase = 'PASSW0RD' # for lack of a better guess
    if configdata['hardwaremanagement.manager']:
        bmc = configdata['hardwaremanagement.manager']
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
    def __init__(node, config, **kwargs):
        crypt = config.decrypt
        config.decrypt = True
        configdata = config.get_node_attributes([node],
            ['secret.ipmiuser', 'secret.ipmipassphrase',
             'secret.managementuser', 'secret.managementpassphrase',
             'hardwaremanagement.manager'])
        connparams = get_conn_params(node, configdata)
        self.username = connparams['username']
        self.password = connparams['passphrase']
        self.kg = connparams['kg']
        self.bmc = connparams['bmc']
        self.port = connparams['port']
        # Cannot actually create console until 'connect', when we get callback

    def connect(callback, **kwargs):
        self.solconnection = console.Console(bmc=self.bmc,
                                             port=self.port,
                                             username=self.username,
                                             password=self.password,
                                             kg=self.kg,
                                             iohandler=callback)
        if _loopthread is None:
            _loopthread = eventlet.spawn(_ipmi_evtloop)

    def write(self, data, **kwargs):
        self.solconnection.send_data(data)


def create(nodes, element, configmanager, **kwargs):
    if element == '_console/session':
        if len(nodes) > 1:
            raise Exception("_console/session does not support multiple nodes")
        return Console(nodes[0], configmanager)
    else:
        raise Exception(
            "TODO(jbjohnso): ipmi api implementation of %s" % element)


def retrieve(nodes, element, configmanager, **kwargs):
    raise Exception("TODO(jbjohnso): ipmi get implementation of %s" % element)
