# Copyright 2014 IBM Corporation
# Copyright 2015 Lenovo
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import confluent.exceptions as exc
import confluent.interface.console as conapi
import confluent.messages as msg
import eventlet
import eventlet.event
import eventlet.green.threading as threading
import eventlet.greenpool as greenpool
import eventlet.queue
import pyghmi.constants as pygconstants
import pyghmi.exceptions as pygexc
import pyghmi.ipmi.console as console
import pyghmi.ipmi.command as ipmicommand
import socket

console.session.select = eventlet.green.select
console.session.threading = eventlet.green.threading

_ipmithread = None
_ipmiwaiters = []

sensor_categories = {
    'temperature': frozenset(['Temperature']),
    'power': frozenset(['Current', 'Battery']),
    'fans': frozenset(['Fan', 'Cooling Device']),
}

def simplify_name(name):
    return name.lower().replace(' ', '_')


class IpmiCommandWrapper(ipmicommand.Command):
    def __init__(self, node, cfm, **kwargs):
        self._attribwatcher = cfm.watch_attributes(
            (node,),('secret.hardwaremanagementuser',
                     'secret.hardwaremanagementpassword', 'secret.ipmikg',
                     'hardwaremanagement.manager'), self._attribschanged)
        super(self.__class__, self).__init__(**kwargs)

    def _attribschanged(self, nodeattribs, configmanager, **kwargs):
        try:
            self.ipmi_session._mark_broken()
        except AttributeError:
            # if ipmi_session doesn't already exist,
            # then do nothing
            pass

def _ipmi_evtloop():
    while True:
        try:
            console.session.Session.wait_for_rsp(timeout=600)
            while _ipmiwaiters:
                waiter = _ipmiwaiters.pop()
                waiter.send()
        except:  # TODO(jbjohnso): log the trace into the log
            import traceback

            traceback.print_exc()


def get_conn_params(node, configdata):
    if 'secret.hardwaremanagementuser' in configdata:
        username = configdata['secret.hardwaremanagementuser']['value']
    else:
        username = 'USERID'
    if 'secret.hardwaremanagementpassword' in configdata:
        passphrase = configdata['secret.hardwaremanagementpassword']['value']
    else:
        passphrase = 'PASSW0RD'  # for lack of a better guess
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


_configattributes = ('secret.hardwaremanagementuser',
                     'secret.hardwaremanagementpassword',
                     'secret.ipmikg', 'hardwaremanagement.manager')


def _donothing(data):
    # a dummy function to avoid some awkward exceptions from
    # zombie pyghmi console objects
    pass


class IpmiConsole(conapi.Console):
    configattributes = frozenset(_configattributes)

    def __init__(self, node, config):
        self.error = None
        self.datacallback = None
        crypt = config.decrypt
        self.solconnection = None
        config.decrypt = True
        self.broken = False
        configdata = config.get_node_attributes([node], _configattributes)
        connparams = get_conn_params(node, configdata[node])
        config.decrypt = crypt
        self.username = connparams['username']
        self.password = connparams['passphrase']
        self.kg = connparams['kg']
        self.bmc = connparams['bmc']
        self.port = connparams['port']
        self.connected = False
        # Cannot actually create console until 'connect', when we get callback

    def __del__(self):
        self.solconnection = None

    def handle_data(self, data):
        if type(data) == dict:
            if 'error' in data:
                self.solconnection = None
                self.broken = True
                self.error = data['error']
                if self.connected:
                    self.datacallback(conapi.ConsoleEvent.Disconnect)
        else:
            self.datacallback(data)

    def connect(self, callback):
        self.datacallback = callback
        # we provide a weak reference to pyghmi as otherwise we'd
        # have a circular reference and reference counting would never get
        # out...
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
                    break
            if self.broken:
                if (self.error.startswith('Incorrect password') or
                        self.error.startswith('Unauthorized name')):
                    raise exc.TargetEndpointBadCredentials
                else:
                    raise exc.TargetEndpointUnreachable(self.error)
            self.connected = True
        except socket.gaierror as err:
            raise exc.TargetEndpointUnreachable(str(err))

    def close(self):
        if self.solconnection is not None:
            # break the circular reference here
            self.solconnection.out_handler = _donothing
            self.solconnection.close()
        self.solconnection = None
        self.broken = True
        self.error = "closed"

    def write(self, data):
        self.solconnection.send_data(data)

    def send_break(self):
        self.solconnection.send_break()


class IpmiIterator(object):
    def __init__(self, operator, nodes, element, cfg, inputdata):
        self.currdata = None
        crypt = cfg.decrypt
        cfg.decrypt = True
        configdata = cfg.get_node_attributes(nodes, _configattributes)
        cfg.decrypt = crypt
        self.gpile = greenpool.GreenPile()
        for node in nodes:
            self.gpile.spawn(perform_request, operator, node, element,
                             configdata, inputdata, cfg)

    def __iter__(self):
        return self

    def next(self):
        if self.currdata is None:
            self.currdata = self.gpile.next()
        # need to apply any translations between pyghmi and confluent
        try:
            retdata = self.currdata.next()
        except AttributeError:
            if hasattr(self.currdata, 'next'):
                # the attribute error is not the immediate
                # one, raise it to be caught as normal
                raise
            retdata = self.currdata
            self.currdata = None
        return retdata


def perform_request(operator, node, element, configdata, inputdata, cfg):
    try:
        return IpmiHandler(operator, node, element, configdata, inputdata, cfg
                           ).handle_request()
    except pygexc.IpmiException as ipmiexc:
        excmsg = str(ipmiexc)
        if excmsg == 'Session no longer connected':
            return msg.ConfluentTargetTimeout(node)
        else:
            raise


persistent_ipmicmds = {}


class IpmiHandler(object):
    def __init__(self, operation, node, element, cfd, inputdata, cfg):
        self.sensormap = {}
        self.sensorcategory = None
        self.broken = False
        self.error = None
        eventlet.sleep(0)
        self.cfg = cfd[node]
        self.loggedin = False
        self.node = node
        self.element = element
        self.op = operation
        connparams = get_conn_params(node, self.cfg)
        self.ipmicmd = None
        self.inputdata = inputdata
        tenant = cfg.tenant
        self._logevt = None
        if ((node, tenant) not in persistent_ipmicmds or
                not persistent_ipmicmds[(node, tenant)].ipmi_session.logged):
            self._logevt = threading.Event()
            try:
                persistent_ipmicmds[(node, tenant)] = IpmiCommandWrapper(
                    node, cfg, bmc=connparams['bmc'],
                    userid=connparams['username'],
                    password=connparams['passphrase'], kg=connparams['kg'],
                    port=connparams['port'], onlogon=self.logged)
            except socket.gaierror as ge:
                if ge[0] == -2:
                    raise exc.TargetEndpointUnreachable(ge[1])
        self.ipmicmd = persistent_ipmicmds[(node, tenant)]

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
        if self._logevt is not None:
            self._logevt.wait()
        self._logevt = None
        if self.broken:
            if self.error == 'timeout':
                return iter([msg.ConfluentTargetTimeout(self.node)])
            elif ('Unauthorized' in self.error or
                    'Incorrect password' in self.error):
                return iter([msg.ConfluentTargetInvalidCredentials(self.node)])
            elif 'Incorrect password' in self.error:
                return iter([C])
            else:
                raise Exception(self.error)
        if self.element == ['power', 'state']:
            return self.power()
        elif self.element == ['boot', 'nextdevice']:
            return self.bootdevice()
        elif self.element == ['health', 'hardware']:
            return self.health()
        elif self.element == ['identify']:
            return self.identify()
        elif self.element[0] == 'sensors':
            return self.handle_sensors()

    def make_sensor_map(self, sensors=None):
        if sensors is None:
            sensors = self.ipmicmd.get_sensor_descriptions()
        for sensor in sensors:
            resourcename = sensor['name']
            self.sensormap[simplify_name(resourcename)] = resourcename


    def read_sensors(self, sensorname):
        try:
            if sensorname == 'all':
                sensors = self.ipmicmd.get_sensor_descriptions()
                readings = []
                for sensor in filter(self.match_sensor, sensors):
                    try:
                        reading = self.ipmicmd.get_sensor_reading(sensor['name'])
                    except pygexc.IpmiException as ie:
                        if ie.ipmicode == 203:
                            continue
                        raise
                    readings.append(self._dict_sensor(reading))
                yield msg.SensorReadings(readings, name=self.node)
            else:
                self.make_sensor_map()
                if sensorname not in self.sensormap:
                    raise exc.NotFoundException('No such sensor')
                reading = self.ipmicmd.get_sensor_reading(
                    self.sensormap[sensorname])
                yield msg.SensorReadings([self._dict_sensor(reading)],
                                         name=self.node)
        except pygexc.IpmiException:
            yield msg.ConfluentTargetTimeout(self.node)

    def handle_sensors(self):
        if self.element[-1] == '':
            self.element = self.element[:-1]
        if len(self.element) < 3:
            return
        self.sensorcategory = self.element[2]
        if len(self.element) == 3:  # list sensors per category
            return self.list_sensors()
        elif len(self.element) == 4:  # resource requested
            return self.read_sensors(self.element[-1])

    def match_sensor(self, sensor):
        if self.sensorcategory == 'all':
            return True
        if sensor['type'] in sensor_categories[self.sensorcategory]:
            return True
        return False

    def list_sensors(self):
        try:
            sensors = self.ipmicmd.get_sensor_descriptions()
        except pygexc.IpmiException:
            yield msg.ConfluentTargetTimeout(self.node)
        yield msg.ChildCollection('all')
        for sensor in filter(self.match_sensor, sensors):
            yield msg.ChildCollection(simplify_name(sensor['name']))


    @staticmethod
    def _str_health(health):
        if pygconstants.Health.Failed & health:
            health = 'failed'
        elif pygconstants.Health.Critical & health:
            health = 'critical'
        elif pygconstants.Health.Warning & health:
            health = 'warning'
        else:
            health = 'ok'
        return health

    def _dict_sensor(self, pygreading):
        retdict = {'name': pygreading.name, 'value': pygreading.value,
                   'states': pygreading.states, 'units': pygreading.units,
                   'health': self._str_health(pygreading.health)}
        return retdict

    def health(self):
        if 'read' == self.op:
            try:
                response = self.ipmicmd.get_health()
            except pygexc.IpmiException:
                yield msg.ConfluentTargetTimeout(self.node)
                return
            health = response['health']
            health = self._str_health(health)
            yield msg.HealthSummary(health, self.node)
            if 'badreadings' in response:
                badsensors = []
                for reading in response['badreadings']:
                    badsensors.append(self._dict_sensor(reading))
                yield msg.SensorReadings(badsensors, name=self.node)
        else:
            raise exc.InvalidArgumentException('health is read-only')

    def bootdevice(self):
        if 'read' == self.op:
            bootdev = self.ipmicmd.get_bootdev()
            if bootdev['bootdev'] in self.bootdevices:
                bootdev['bootdev'] = self.bootdevices[bootdev['bootdev']]
            bootmode = 'unspecified'
            if 'uefimode' in bootdev:
                if bootdev['uefimode']:
                    bootmode = 'uefi'
                else:
                    bootmode = 'bios'
            return msg.BootDevice(node=self.node,
                                  device=bootdev['bootdev'],
                                  bootmode=bootmode)
        elif 'update' == self.op:
            bootdev = self.inputdata.bootdevice(self.node)
            bootmode = self.inputdata.bootmode(self.node)
            bootdev = self.ipmicmd.set_bootdev(bootdev)
            if bootdev['bootdev'] in self.bootdevices:
                bootdev['bootdev'] = self.bootdevices[bootdev['bootdev']]
            return msg.BootDevice(node=self.node,
                                  device=bootdev['bootdev'])

    def identify(self):
        if 'update' == self.op:
            identifystate = self.inputdata.inputbynode[self.node] == 'on'
            self.ipmicmd.set_identify(on=identifystate)
            return msg.IdentifyState(
                node=self.node, state=self.inputdata.inputbynode[self.node])
        elif 'read' == self.op:
            # ipmi has identify as read-only for now
            return msg.IdentifyState(node=self.node, state='')

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
    if element == ['_console', 'session']:
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
