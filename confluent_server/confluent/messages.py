# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

# This module implements client/server messages emitted from plugins.
# Things are defined here to 'encourage' developers to coordinate information
# format.  This is also how different data formats are supported
import confluent.exceptions as exc
import json

valid_health_values = set([
    'ok',
    'warning',
    'critical',
    'failed',
    'unknown',
])

def _htmlify_structure(indict):
    ret = "<ul>"
    if isinstance(indict, dict):
        for key in indict.iterkeys():
            ret += "<li>{0}: ".format(key)
            if type(indict[key]) in (str, unicode, float, int):
                ret += str(indict[key])
            else:
                ret += _htmlify_structure(indict[key])
    elif isinstance(indict, list):
        if len(indict) > 0:
            if type(indict[0]) in (str, unicode, None):
                nd = []
                for datum in indict:
                    if datum is None:
                        nd.append('')
                    else:
                        nd.append(datum)
                ret += ",".join(nd)
            else:
                for v in indict:
                    ret += _htmlify_structure(v)
    return ret + '</ul>'


class ConfluentMessage(object):
    readonly = False
    defaultvalue = ''
    defaulttype = 'text'

    def __init__(self):
        self.desc = ''
        self.stripped = False
        self.kvpairs = {}
        raise NotImplementedError("Must be subclassed!")

    def json(self):
        # This will create the canonical json representation of this message
        if hasattr(self, 'stripped') and self.stripped:
            datasource = self.kvpairs
        else:
            datasource = {'databynode': self.kvpairs}
        jsonsnippet = json.dumps(datasource, separators=(',', ':'))[1:-1]
        return jsonsnippet

    def raw(self):
        """Return pythonic representation of the response.

        Used by httpapi while assembling data prior to json serialization"""
        if hasattr(self, 'stripped') and self.stripped:
            return self.kvpairs
        return {'databynode': self.kvpairs}

    def strip_node(self, node):
        self.stripped = True
        if self.kvpairs is not None:
            self.kvpairs = self.kvpairs[node]

    def html(self, extension=''):
        # this is used to facilitate the api explorer feature
        if not hasattr(self, 'stripped'):
            self.stripped = False
        if not hasattr(self, 'notnode'):
            self.notnode = False
        if self.stripped or self.notnode:
            return self._generic_html_value(self.kvpairs)
        if not self.stripped:
            htmlout = ''
            for node in self.kvpairs.iterkeys():
                htmlout += '{0}:{1}\n'.format(
                    node, self._generic_html_value(self.kvpairs[node]))
            return htmlout

    def _generic_html_value(self, pairs):
        snippet = ""
        for key in pairs.iterkeys():
            val = pairs[key]
            value = self.defaultvalue
            if isinstance(val, dict) and 'type' in val:
                valtype = val['type']
            else:
                valtype = self.defaulttype
            notes = []

            if isinstance(val, list):
                snippet += key + ":"
                if len(val) == 0 and not self.readonly:
                    snippet += ('<input type="{0}" name="{1}" value="" '
                                ' "title="{2}">'
                                ).format(valtype, key, self.desc)
                for v in val:
                    if self.readonly:
                        snippet += _htmlify_structure(v)
                    else:
                        snippet += ('<input type="{0}" name="{1}" value="{2}" '
                                    ' "title="{3}">\r'
                                    ).format(valtype, key, v, self.desc)
                if not self.readonly:
                    snippet += (
                        '<input type="{0}" name="{1}" value="" title="{2}">'
                        '<input type="checkbox" name="restexplorerhonorkey" '
                        'value="{1}">\r').format(valtype, key, self.desc)
                return snippet
            if val is not None and 'value' in val:
                value = val['value']
                if 'inheritedfrom' in val:
                    notes.append('Inherited from %s' % val['inheritedfrom'])
                if 'expression' in val:
                    notes.append(
                        'Derived from expression "%s"' % val['expression'])
            elif val is not None and 'expression' in val and 'broken' in val:
                value = "*BROKEN*"
                notes.append(
                    'Derived from expression "%s"' % val['expression'])
                notes.append('Broken because of %s' % val['broken'])
            elif val is not None and 'expression' in val:
                value = val['expression']
            if value is None:
                value = ''
            if val is not None and value == '' and 'isset' in val and val[
                    'isset'] is True:
                # an encrypted value, put some *** to show it is set
                # in the explorer
                if 'inheritedfrom' in val:
                    notes.append('Inherited from %s' % val['inheritedfrom'])
                value = '********'
            if self.readonly:
                snippet += "{0}: {1}".format(key, value)
            else:
                snippet += (key + ":" +
                            '<input type="{0}" name="{1}" value="{2}" '
                            'title="{3}"><input type="checkbox" '
                            'name="restexplorerhonorkey" value="{1}"><br>\r'
                            ).format(valtype, key, value, self.desc)
            if len(notes) > 0:
                snippet += '(' + ','.join(notes) + ')'
        return snippet


class ConfluentNodeError(object):
    def __init__(self, node, errorstr):
        self.node = node
        self.error = errorstr

    def raw(self):
        return {'databynode': {self.node: {'error': self.error}}}

    def html(self):
        return self.node + ":" + self.error

    def strip_node(self, node):
        # NOTE(jjohnson2): For single node errors, raise exception to
        # trigger what a developer of that medium would expect
        raise Exception(self.error)


class ConfluentTargetTimeout(ConfluentNodeError):
    def __init__(self, node, errstr='timeout'):
        self.node = node
        self.error = errstr

    def strip_node(self, node):
        raise exc.TargetEndpointUnreachable(self.error)


class ConfluentTargetNotFound(ConfluentNodeError):
    def __init__(self, node, errorstr='not found'):
        self.node = node
        self.error = errorstr

    def strip_node(self, node):
        raise exc.NotFoundException(self.error)


class ConfluentTargetInvalidCredentials(ConfluentNodeError):
    def __init__(self, node):
        self.node = node
        self.error = 'bad credentials'

    def strip_node(self, node):
        raise exc.TargetEndpointBadCredentials


class DeletedResource(ConfluentMessage):
    def __init__(self, resource):
        self.kvpairs = {}


class ConfluentChoiceMessage(ConfluentMessage):
    valid_values = set()
    valid_paramset = {}

    def __init__(self, node, state):
        self.stripped = False
        self.kvpairs = {
            node: {
                self.keyname: {'value': state},
            }
        }

    def html(self, extension=''):
        if hasattr(self, 'stripped') and self.stripped:
            return self._create_option(self.kvpairs)
        else:
            htmlout = ''
            for node in self.kvpairs.iterkeys():
                htmlout += '{0}:{1}\n'.format(
                    node, self._create_option(self.kvpairs[node]))
            return htmlout

    def _create_option(self, pairdata):
        snippet = ''
        for key in pairdata.iterkeys():
            val = pairdata[key]
            snippet += key + ':<select name="%s">' % key
            valid_values = self.valid_values
            if key in self.valid_paramset:
                valid_values = self.valid_paramset[key]
            for opt in valid_values:
                if opt == val['value']:
                    snippet += '<option value="%s" selected>%s</option>\r' % (
                        opt, opt)
                else:
                    snippet += '<option value="%s">%s</option>\r' % (opt, opt)
            snippet += '</select>'
            snippet += '<input type="checkbox" name="restexplorerhonorkey" '
            snippet += 'value="{0}"><br>\r'.format(key)
        return snippet


class LinkRelation(ConfluentMessage):
    kvpairs = None

    def __init__(self):
        self.href = ''
        self.rel = ''

    def json(self):
        """Provide json_hal style representation of the relation.

        This currently only makes sense for the socket api.
        """
        return {self.rel: '{ "href": "%s" }' % self.href}

    def raw(self):
        """Provide python structure of the relation.

        This currently is only sensible to consume from httpapi.
        """
        return {self.rel: {"href": self.href}}

    def html(self, extension=''):
        """Provide an html representation of the link relation.

        This is used by the API explorer aspect of httpapi"""
        return '<a href="{0}{2}" rel="{1}">{0}{2}</a>'.format(self.href,
                                                              self.rel,
                                                              extension)
        # return '<a href="%s" rel="%s">%s</a><input type="submit"
        # name="restexprerorop" value="delete:%s"' % (self.href, self.rel,
        # self.href, self.href)


class ChildCollection(LinkRelation):
    def __init__(self, collname, candelete=False):
        self.rel = 'item'
        self.href = collname
        self.candelete = candelete

    def html(self, extension=''):
        if self.candelete:
            return (
                '<a href="{0}{2}" rel="{1}">{0}{2}</a> . . . . . . . . . . . . '
                '<button type="submit" name="restexplorerop" '
                'value="delete" formaction="{0}">delete'
                '</button>').format(self.href, self.rel, extension)
        else:
            return '<a href="{0}{1}" rel="{0}">{0}{1}</a>'.format(self.href,
                                                                  extension)


def get_input_message(path, operation, inputdata, nodes=None, multinode=False):
    if path[0] == 'power' and path[1] == 'state' and operation != 'retrieve':
        return InputPowerMessage(path, nodes, inputdata)
    elif path[0] in ('attributes', 'users') and operation != 'retrieve':
        return InputAttributes(path, inputdata, nodes)
    elif path == ['boot', 'nextdevice'] and operation != 'retrieve':
        return InputBootDevice(path, nodes, inputdata)
    elif (len(path) == 5 and
            path[:4] == ['configuration', 'management_controller', 'alerts',
                         'destinations'] and operation != 'retrieve'):
        return InputAlertDestination(path, nodes, inputdata, multinode)
    elif path == ['identify'] and operation != 'retrieve':
        return InputIdentifyMessage(path, nodes, inputdata)
    elif path == ['events', 'hardware', 'decode']:
        return InputAlertData(path, inputdata, nodes)
    elif (path[:3] == ['configuration', 'management_controller', 'users'] and
            operation not in ('retrieve', 'delete') and path[-1] != 'all'):
        return InputCredential(path, inputdata, nodes)
    elif inputdata:
        raise exc.InvalidArgumentException()


class InputAlertData(ConfluentMessage):

    def __init__(self, path, inputdata, nodes=None):
        self.alertparams = inputdata
        # first migrate snmpv1 input to snmpv2 format
        if 'specifictrap' in self.alertparams:
            # If we have a 'specifictrap', convert to SNMPv2 per RFC 2576
            # This way
            enterprise = self.alertparams['enterprise']
            specifictrap = self.alertparams['specifictrap']
            self.alertparams['.1.3.6.1.6.3.1.1.4.1.0'] = enterprise + '.0.' + \
                str(specifictrap)
        if '1.3.6.1.6.3.1.1.4.1.0' in self.alertparams:
            self.alertparams['.1.3.6.1.6.3.1.1.4.1.0'] = \
                self.alertparams['1.3.6.1.6.3.1.1.4.1.0']
        if '.1.3.6.1.6.3.1.1.4.1.0' not in self.alertparams:
            raise exc.InvalidArgumentException('Missing SNMP Trap OID')

    def get_alert(self, node=None):
        return self.alertparams


class InputAttributes(ConfluentMessage):
    def __init__(self, path, inputdata, nodes=None):
        self.nodeattribs = {}
        nestedmode = False
        if not inputdata:
            raise exc.InvalidArgumentException('no request data provided')
        if nodes is None:
            self.attribs = inputdata
            for attrib in self.attribs:
                if type(self.attribs[attrib]) in (str, unicode):
                    try:
                        # ok, try to use format against the string
                        # store back result to the attribute to
                        # handle things like '{{' and '}}'
                        # if any weird sort of error should
                        # happen, it means the string has something
                        # that formatter is looking to fulfill, but
                        # is unable to do so, meaning it is an expression
                        tv = self.attribs[attrib].format()
                        self.attribs[attrib] = tv
                    except (KeyError, IndexError):
                        # this means format() actually thought there was work
                        # that suggested parameters, push it in as an
                        # expression
                        self.attribs[attrib] = {
                            'expression': self.attribs[attrib]}
            return
        for node in nodes:
            if node in inputdata:
                nestedmode = True
                self.nodeattribs[node] = inputdata[node]
        if nestedmode:
            for key in inputdata:
                if key not in nodes:
                    raise exc.InvalidArgumentException
        else:
            for node in nodes:
                self.nodeattribs[node] = inputdata

    def get_attributes(self, node):
        if node not in self.nodeattribs:
            return {}
        nodeattr = self.nodeattribs[node]
        for attr in nodeattr:
            if type(nodeattr[attr]) in (str, unicode):
                try:
                    # as above, use format() to see if string follows
                    # expression, store value back in case of escapes
                    tv = nodeattr[attr].format()
                    nodeattr[attr] = tv
                except (KeyError, IndexError):
                    # an expression string will error if format() done
                    # use that as cue to put it into config as an expr
                    nodeattr[attr] = {'expression': nodeattr[attr]}
        return nodeattr


class InputCredential(ConfluentMessage):
    valid_privilege_levels = set([
        'callback',
        'user',
        'operator',
        'administrator',
        'proprietary',
        'no_access',
    ])

    valid_enabled_values = set([
        'yes',
        'no'
    ])

    def __init__(self, path, inputdata, nodes=None):
        self.credentials = {}
        nestedmode = False
        if not inputdata:
            raise exc.InvalidArgumentException('no request data provided')

        if len(path) == 4:
            inputdata['uid'] = path[-1]
        # if the operation is 'create' check if all fields are present
        elif ('uid' not in inputdata or 'privilege_level' not in inputdata or
                'username' not in inputdata or 'password' not in inputdata):
            raise exc.InvalidArgumentException('all fields are required')

        if 'uid' not in inputdata:
            raise exc.InvalidArgumentException('uid is missing')
        if (isinstance(inputdata['uid'], str) and
                not inputdata['uid'].isdigit()):
            raise exc.InvalidArgumentException('uid must be a number')
        else:
            inputdata['uid'] = int(inputdata['uid'])
        if ('privilege_level' in inputdata and
              inputdata['privilege_level'] not in self.valid_privilege_levels):
            raise exc.InvalidArgumentException('privilege_level is not one of '
                                        + ','.join(self.valid_privilege_levels))
        if 'username' in inputdata and len(inputdata['username']) > 16:
            raise exc.InvalidArgumentException(
                                        'name must be less than or = 16 chars')
        if 'password' in inputdata and len(inputdata['password']) > 20:
            raise exc.InvalidArgumentException('password has limit of 20 chars')

        if ('enabled' in inputdata and
            inputdata['enabled'] not in self.valid_enabled_values):
            raise exc.InvalidArgumentException('valid values for enabled are '
                                                            + 'yes and no')

        if nodes is None:
            raise exc.InvalidArgumentException(
                'This only supports per-node input')
        for node in nodes:
            self.credentials[node] = inputdata

    def get_attributes(self, node):
        if node not in self.credentials:
            return {}
        credential = self.credentials[node]
        for attr in credentials:
            if type(credentials[attr]) in (str, unicode):
                try:
                    # as above, use format() to see if string follows
                    # expression, store value back in case of escapes
                    tv = credential[attr].format()
                    credential[attr] = tv
                except (KeyError, IndexError):
                    # an expression string will error if format() done
                    # use that as cue to put it into config as an expr
                    credential[attr] = {'expression': credential[attr]}
        return credential


class ConfluentInputMessage(ConfluentMessage):
    keyname = 'state'

    def __init__(self, path, nodes, inputdata):
        self.inputbynode = {}
        self.stripped = False
        if not inputdata:
            raise exc.InvalidArgumentException('missing input data')
        if self.keyname not in inputdata:
            # assume we have nested information
            for key in nodes:
                if key not in inputdata:
                    raise exc.InvalidArgumentException(key + ' not in request')
                datum = inputdata[key]
                if self.keyname not in datum:
                    raise exc.InvalidArgumentException(
                        'missing {0} argument'.format(self.keyname))
                elif datum[self.keyname] not in self.valid_values:
                    raise exc.InvalidArgumentException(
                        datum[self.keyname] + ' is not one of ' +
                        ','.join(self.valid_values))
                self.inputbynode[key] = datum[self.keyname]
        else:  # we have a state argument not by node
            datum = inputdata
            if self.keyname not in datum:
                raise exc.InvalidArgumentException(
                    'missing {0} argument'.format(self.keyname))
            elif datum[self.keyname] not in self.valid_values:
                raise exc.InvalidArgumentException(datum[self.keyname] +
                                                   ' is not one of ' +
                                                   ','.join(self.valid_values))
            for node in nodes:
                self.inputbynode[node] = datum[self.keyname]


class InputIdentifyMessage(ConfluentInputMessage):
    valid_values = set([
        'on',
        'off',
    ])

    keyname = 'identify'


class InputPowerMessage(ConfluentInputMessage):
    valid_values = set([
        'on',
        'off',
        'reset',
        'boot',
        'shutdown',
    ])

    def powerstate(self, node):
        return self.inputbynode[node]


class BootDevice(ConfluentChoiceMessage):
    valid_values = set([
        'network',
        'hd',
        'setup',
        'default',
        'cd',
    ])

    valid_bootmodes = set([
        'unspecified',
        'bios',
        'uefi',
    ])

    valid_paramset = {
        'bootmode': valid_bootmodes,
        }


    def __init__(self, node, device, bootmode='unspecified'):
        if device not in self.valid_values:
            raise Exception("Invalid boot device argument passed in:" +
                            repr(device))
        if bootmode not in self.valid_bootmodes:
            raise Exception("Invalid boot mode argument passed in:" +
                            repr(bootmode))
        self.kvpairs = {
            node: {
                'nextdevice': {'value': device},
                'bootmode': {'value': bootmode},
            }
        }


class InputBootDevice(BootDevice):
    def __init__(self, path, nodes, inputdata):
        self.bootdevbynode = {}
        self.bootmodebynode = {}
        if not inputdata:
            raise exc.InvalidArgumentException()
        if 'nextdevice' not in inputdata:
            for key in nodes:
                if key not in inputdata:
                    raise exc.InvalidArgumentException(key + ' not in request')
                datum = inputdata[key]
                if 'nextdevice' not in datum:
                    raise exc.InvalidArgumentException(
                        'missing nextdevice argument')
                elif datum['nextdevice'] not in self.valid_values:
                    raise exc.InvalidArgumentException(
                        datum['nextdevice'] + ' is not one of ' +
                        ','.join(self.valid_values))
                self.bootdevbynode[key] = datum['nextdevice']
                if 'bootmode' in datum:
                    if datum['bootmode'] not in self.valid_bootmodes:
                        raise exc.InvalidArgumentException(
                            datum['bootmode'] + ' is not one of ' +
                            ','.join(self.valid_bootmodes))
                    self.bootmodebynode[key] = datum['bootmode']
        else:
            datum = inputdata
            if 'nextdevice' not in datum:
                raise exc.InvalidArgumentException(
                    'missing nextdevice argument')
            elif datum['nextdevice'] not in self.valid_values:
                raise exc.InvalidArgumentException(
                    datum['nextdevice'] + ' is not one of ' +
                    ','.join(self.valid_values))
            for node in nodes:
                self.bootdevbynode[node] = datum['nextdevice']
                if 'bootmode' in datum:
                    self.bootmodebynode[node] = datum['bootmode']

    def bootdevice(self, node):
        return self.bootdevbynode[node]

    def bootmode(self, node):
        return self.bootmodebynode.get(node, 'unspecified')


class IdentifyState(ConfluentChoiceMessage):
    valid_values = set([
        '',  # allowed for output to indicate write-only support
        'on',
        'off',
    ])
    keyname = 'identify'


class PowerState(ConfluentChoiceMessage):
    valid_values = set([
        'on',
        'off',
        'reset',
        'boot',
    ])
    keyname = 'state'


class EventCollection(ConfluentMessage):
    """A collection of events

    This conveys a representation of an iterable of events.  The following
    fields are supported:
    id (some data giving the class of event without the specific data of the
        event.  For example, 'overtemp (1000 degrees celsius)' would have
        the same 'id' as 'overtemp (200 degrees celsius)
    component  (specific name of the component this event references if any)
    component_type (A description of the sort of device component is)
    event (A text description of the event that occurred)
    severity (The text 'ok', 'warning', 'critical', 'failed', or 'unknown')
    timestamp (ISO 8601 compliant timestamp if available)
    """
    readonly = True

    def __init__(self, events=(), name=None):
        eventdata = []
        self.notnode = name is None
        for event in events:
            entry = {
                'id': event.get('id', None),
                'component': event.get('component', None),
                'component_type': event.get('component_type', None),
                'event': event.get('event', None),
                'severity': event['severity'],
                'timestamp': event.get('timestamp', None),
                'record_id': event.get('record_id', None),
            }
            if event['severity'] not in valid_health_values:
                raise exc.NotImplementedException(
                    'Invalid severity - ' + repr(event['severity']))
            eventdata.append(entry)
        if self.notnode:
            self.kvpairs = {'events': eventdata}
        else:
            self.kvpairs = {name: {'events': eventdata}}


class User(ConfluentMessage):
    def __init__(self, uid, username, privilege_level, name=None):
        self.desc = 'foo'
        self.stripped = False
        self.notnode = name is None
        kvpairs = {'username': {'value': username},
                   'password': {'value': '', 'type': 'password'},
                   'privilege_level': {'value': privilege_level},
                   'enabled': {'value': ''}
                   }
        if self.notnode:
            self.kvpairs = kvpairs
        else:
            self.kvpairs = {name: kvpairs}


class UserCollection(ConfluentMessage):
    readonly = True

    def __init__(self, users=(), name=None):
        self.notnode = name is None
        self.desc = 'list of users'
        userlist = []
        for user in users:
            entry = {
                'uid': user['uid'],
                'username': user['name'],
                'privilege_level': user['access']['privilege_level']
            }
            userlist.append(entry)
        if self.notnode:
            self.kvpairs = {'users': userlist}
        else:
            self.kvpairs = {name: {'users': userlist}}


class AlertDestination(ConfluentMessage):
    def __init__(self, ip, acknowledge=False, retries=0, name=None):
        self.desc = 'foo'
        self.stripped = False
        self.notnode = name is None
        kvpairs = {'ip': {'value': ip},
                   'acknowledge': {'value': acknowledge},
                   'retries': {'value': retries}}
        if self.notnode:
            self.kvpairs = kvpairs
        else:
            self.kvpairs = {name: kvpairs}


class InputAlertDestination(ConfluentMessage):
    valid_alert_params = {
        'acknowledge': lambda x: False if type(x) in (unicode,str) and x.lower() == 'false' else bool(x),
        'ip': lambda x: x,
        'retries': lambda x: int(x)
    }

    def __init__(self, path, nodes, inputdata, multinode=False):
        self.alertcfg = {}
        if multinode:  # keys are node names
            for node in inputdata:
                self.alertcfg[node] = inputdata[node]
                for key in inputdata[node]:
                    if key not in self.valid_alert_params:
                        raise exc.InvalidArgumentException(
                            'Unrecognized alert parameter ' + key)
                    if isinstance(inputdata[node][key], dict):
                        self.alertcfg[node][key] = \
                            self.valid_alert_params[key](
                                inputdata[node][key]['value'])
                    else:
                        self.alertcfg[node][key] = \
                            self.valid_alert_params[key](inputdata[node][key])
        else:
            for key in inputdata:
                if key not in self.valid_alert_params:
                    raise exc.InvalidArgumentException(
                            'Unrecognized alert parameter ' + key)
                if isinstance(inputdata[key], dict):
                    inputdata[key] = self.valid_alert_params[key](
                        inputdata[key]['value'])
                else:
                    inputdata[key] = self.valid_alert_params[key](
                        inputdata[key])
            for node in nodes:
                self.alertcfg[node] = inputdata

    def alert_params_by_node(self, node):
        return self.alertcfg[node]


class SensorReadings(ConfluentMessage):
    readonly = True

    def __init__(self, sensors=(), name=None):
        readings = []
        self.notnode = name is None
        for sensor in sensors:
            sensordict = {'name': sensor.name}
            if hasattr(sensor, 'value'):
                sensordict['value'] = sensor.value
            if hasattr(sensor, 'units'):
                sensordict['units'] = sensor.units
            if hasattr(sensor, 'states'):
                sensordict['states'] = sensor.states
            if hasattr(sensor, 'state_ids'):
                sensordict['state_ids'] = sensor.state_ids
            if hasattr(sensor, 'health'):
                sensordict['health'] = sensor.health
            if hasattr(sensor, 'type'):
                sensordict['type'] = sensor.type
            readings.append(sensordict)
        if self.notnode:
            self.kvpairs = {'sensors': readings}
        else:
            self.kvpairs = {name: {'sensors': readings}}


class Firmware(ConfluentMessage):
    readonly = True

    def __init__(self, data, name):
        self.notnode = name is None
        self.desc = 'Firmware information'
        if self.notnode:
            self.kvpairs = {'firmware': data}
        else:
            self.kvpairs = {name:  {'firmware': data}}


class KeyValueData(ConfluentMessage):
    readonly = True

    def __init__(self, kvdata, name=None):
        self.notnode = name is None
        if self.notnode:
            self.kvpairs = kvdata
        else:
            self.kvpairs = {name: kvdata}


class LEDStatus(ConfluentMessage):
    readonly = True

    def __init__(self, data, name):
        self.notnode = name is None
        self.desc = 'led status'

        if self.notnode:
            self.kvpairs = {'leds':data}
        else:
            self.kvpairs = {name: {'leds':data}}


class NetworkConfiguration(ConfluentMessage):
    desc = 'Network configuration'

    def __init__(self, name=None, ipv4addr=None, ipv4gateway=None,
                 ipv4cfgmethod=None, hwaddr=None):
        self.notnode = name is None
        self.stripped = False

        kvpairs = {
            'ipv4_address': {'value': ipv4addr},
            'ipv4_gateway': {'value': ipv4gateway},
            'ipv4_configuration': {'value': ipv4cfgmethod},
            'hw_addr': {'value': hwaddr},
        }
        if self.notnode:
            self.kvpairs = kvpairs
        else:
            self.kvpairs = {name: kvpairs}


class HealthSummary(ConfluentMessage):
    readonly = True
    valid_values = valid_health_values

    def __init__(self, health, name=None):
        self.stripped = False
        self.notnode = name is None
        if health not in self.valid_values:
            raise ValueError("%d is not a valid health state" % health)
        if self.notnode:
            self.kvpairs = {'health': {'value': health}}
        else:
            self.kvpairs = {name: {'health': {'value': health}}}


class Attributes(ConfluentMessage):
    def __init__(self, name=None, kv=None, desc=''):
        self.desc = desc
        nkv = {}
        self.notnode = name is None
        for key in kv.iterkeys():
            if type(kv[key]) in (str, unicode):
                nkv[key] = {'value': kv[key]}
            else:
                nkv[key] = kv[key]
        if self.notnode:
            self.kvpairs = nkv
        else:
            self.kvpairs = {
                name: nkv
            }


class ListAttributes(ConfluentMessage):
    def __init__(self, name=None, kv=None, desc=''):
        self.desc = desc
        self.notnode = name is None
        if self.notnode:
            self.kvpairs = kv
        else:
            self.kvpairs = {name: kv}


class CryptedAttributes(Attributes):
    defaulttype = 'password'

    def __init__(self, name=None, kv=None, desc=''):
        # for now, just keep the dictionary keys and discard crypt value
        self.desc = desc
        nkv = {}
        for key in kv.iterkeys():
            nkv[key] = {'isset': False}
            try:
                if kv[key] is not None and kv[key]['cryptvalue'] != '':
                    nkv[key] = {'isset': True}
                    nkv[key]['inheritedfrom'] = kv[key]['inheritedfrom']
            except KeyError:
                pass
        self.notnode = name is None
        if self.notnode:
            self.kvpairs = nkv
        else:
            self.kvpairs = {
                name: nkv
            }
