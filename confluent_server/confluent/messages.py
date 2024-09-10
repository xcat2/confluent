# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 IBM Corporation
# Copyright 2015-2019 Lenovo
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
import confluent.config.configmanager as cfm
import confluent.config.conf as cfgfile
from copy import deepcopy
from datetime import datetime
import confluent.util as util
import msgpack
import json

try:
    unicode
except NameError:
    unicode = str

valid_health_values = set([
    'ok',
    'warning',
    'critical',
    'failed',
    'unknown',
])

passcomplexity = cfgfile.get_option('policy', 'passwordcomplexity')
passminlength = cfgfile.get_option('policy', 'passwordminlength')
if passminlength:
    passminlength = int(passminlength)
else:
    passminlength = 0
if passcomplexity:
    passcomplexity = int(passcomplexity)
else:
    passcomplexity = 0

def simplify_name(name):
    return name.lower().replace(' ', '_').replace('/', '-').replace(
        '_-_', '-')


def _htmlify_structure(indict):
    ret = "<ul>"
    if isinstance(indict, dict):
        for key in sorted(indict):
            ret += "<li>{0}: ".format(key)
            if type(indict[key]) in (bytes, unicode):
                ret += util.stringify(indict[key])
            if type(indict[key]) in (float, int):
                ret += str(indict[key])
            elif isinstance(indict[key], datetime):
                ret += indict[key].strftime('%Y-%m-%dT%H:%M:%S')
            else:
                ret += _htmlify_structure(indict[key])
    elif isinstance(indict, list):
        if len(indict) > 0:
            if type(indict[0]) in (bytes, unicode, None):
                nd = []
                for datum in indict:
                    if datum is None:
                        nd.append('')
                    else:
                        nd.append(util.stringify(datum))
                ret += ",".join(nd)
            else:
                for v in indict:
                    ret += _htmlify_structure(v)
    return ret + '</ul>'


def msg_deserialize(packed):
    m = msgpack.unpackb(packed, raw=False)
    cls = globals()[m[0]]
    if issubclass(cls, ConfluentMessage) or issubclass(cls, ConfluentNodeError):
        return cls(*m[1:])
    raise Exception("Unknown shenanigans")


class ConfluentMessage(object):
    apicode = 200
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
        jsonsnippet = json.dumps(datasource, sort_keys=True, separators=(',', ':'))[1:-1]
        return jsonsnippet

    def serialize(self):
        msg = [self.__class__.__name__]
        msg.extend(self.myargs)
        return msgpack.packb(msg, use_bin_type=False)

    @classmethod
    def deserialize(cls, data):
        return cls(*data)

    def raw(self):
        """Return pythonic representation of the response.

        Used by httpapi while assembling data prior to json serialization"""
        if ((hasattr(self, 'stripped') and self.stripped) or
                (hasattr(self, 'notnode') and self.notnode)):
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
            for node in self.kvpairs:
                htmlout += '{0}:{1}\n'.format(
                    node, self._generic_html_value(self.kvpairs[node]))
            return htmlout

    def _generic_html_value(self, pairs):
        snippet = ""
        for key in pairs:
            val = pairs[key]
            key = util.stringify(key)
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
            if (isinstance(val, bool) or isinstance(val, bytes) or
                    isinstance(val, unicode)):
                value = str(val)
            elif isinstance(val, int):
                value = '{0}'.format(int)
            elif val is not None and 'value' in val:
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
            elif isinstance(val, dict):
                value = _htmlify_structure(val)
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
                snippet += "{0}: {1}<br>".format(key, value)
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
    apicode = 500

    def __init__(self, node, errorstr):
        self.node = node
        self.error = errorstr

    def serialize(self):
        return msgpack.packb(
            [self.__class__.__name__, self.node, self.error],
            use_bin_type=False)

    @classmethod
    def deserialize(cls, data):
        return cls(*data)

    def raw(self):
        return {'databynode': {self.node: {'errorcode': self.apicode,
                                           'error': self.error}}}

    def html(self):
        return self.node + ":" + self.error

    def strip_node(self, node):
        # NOTE(jjohnson2): For single node errors, raise exception to
        # trigger what a developer of that medium would expect
        raise Exception('{0}: {1}'.format(self.node, self.error))


class Generic(ConfluentMessage):

    def __init__(self, data):
        self.data = data

    def json(self):
        return json.dumps(self.data)

    def raw(self):
        return self.data

    def html(self):
        return json.dumps(self.data)


class ConfluentResourceUnavailable(ConfluentNodeError):
    apicode = 503

    def __init__(self, node, errstr='Unavailable'):
        self.node = node
        self.error = errstr

    def strip_node(self, node):
        raise exc.TargetResourceUnavailable()


class ConfluentTargetTimeout(ConfluentNodeError):
    apicode = 504

    def __init__(self, node, errstr='timeout'):
        self.node = node
        self.error = errstr


    def strip_node(self, node):
        raise exc.TargetEndpointUnreachable(self.error)


class ConfluentTargetNotFound(ConfluentNodeError):
    apicode = 404

    def __init__(self, node, errorstr='not found'):
        self.node = node
        self.error = errorstr

    def strip_node(self, node):
        raise exc.NotFoundException(self.error)


class ConfluentTargetInvalidCredentials(ConfluentNodeError):
    apicode = 502
    def __init__(self, node, errstr='bad credentials'):
        self.node = node
        self.error = errstr

    def strip_node(self, node):
        raise exc.TargetEndpointBadCredentials


class DeletedResource(ConfluentMessage):
    notnode = True
    def __init__(self, resource):
        self.myargs = [resource]
        self.desc = 'Delete Resource'
        self.kvpairs = {'deleted': resource}

    def strip_node(self, node):
        pass


class ConfluentResourceNotFound(ConfluentMessage):
    notnode = True
    apicode = 404

    def __init__(self, resource):
        self.myargs = [resource]
        self.desc = 'Not Found'
        self.kvpairs = {'missing': resource}

    def strip_node(self, node):
        pass

class ConfluentResourceCount(ConfluentMessage):
    notnode = True

    def __init__(self, count):
        self.myargs = [count]
        self.desc = 'Resource Count'
        self.kvpairs = {'count': count}

    def strip_node(self, node):
        pass

class CreatedResource(ConfluentMessage):
    notnode = True
    readonly = True

    def __init__(self, resource):
        self.myargs = [resource]
        self.desc = 'Create Resource'
        self.kvpairs = {'created': resource}

    def strip_node(self, node):
        pass


class RenamedResource(ConfluentMessage):
    notnode = True
    readonly = True

    def __init__(self, oldname, newname):
        self.myargs = (oldname, newname)
        self.kvpairs = {'oldname': oldname, 'newname': newname}

    def strip_node(self, node):
        pass


class RenamedNode(ConfluentMessage):
    def __init__(self, name, rename):
        self.myargs = (name, rename)
        self.desc = 'New Name'
        kv = {'rename': {'value': rename}}
        self.kvpairs = {name: kv}


class AssignedResource(ConfluentMessage):
    notnode = True
    readonly = True

    def __init__(self, resource):
        self.myargs = [resource]
        self.kvpairs = {'assigned': resource}


class ConfluentChoiceMessage(ConfluentMessage):
    valid_values = set()
    valid_paramset = {}

    def __init__(self, node, state):
        self.myargs = (node, state)
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
            for node in self.kvpairs:
                htmlout += '{0}:{1}\n'.format(
                    node, self._create_option(self.kvpairs[node]))
            return htmlout

    def _create_option(self, pairdata):
        snippet = ''
        for key in pairdata:
            val = pairdata[key]
            key = util.stringify(key)
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
        self.myargs = (collname, candelete)
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


# TODO(jjohnson2): enhance the following to support expressions:
# InputNetworkConfiguration
# InputMCI
# InputDomainName
# InputNTPServer
def get_input_message(path, operation, inputdata, nodes=None, multinode=False,
                      configmanager=None):
    if path[0] == 'power' and path[1] == 'state' and operation != 'retrieve':
        return InputPowerMessage(path, nodes, inputdata)
    elif (path in (['power', 'reseat'], ['_enclosure', 'reseat_bay']) and
            operation != 'retrieve'):
        return InputReseatMessage(path, nodes, inputdata)
    elif path == ['attributes', 'expression']:
        return InputExpression(path, inputdata, nodes)
    elif path == ['attributes', 'rename']:
        return InputConfigChangeSet(path, inputdata, nodes, configmanager)
    elif path[0] in ('attributes', 'users', 'usergroups') and operation != 'retrieve':
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
    elif (path[:3] == ['configuration', 'management_controller', 'reset']
            and operation != 'retrieve'):
        return InputBMCReset(path, nodes, inputdata)
    elif (path[:3] == ['configuration', 'management_controller', 'identifier']
            and operation != 'retrieve'):
        return InputMCI(path, nodes, inputdata)
    elif (path[:3] == ['configuration', 'management_controller', 'hostname']
            and operation != 'retrieve'):
        return InputHostname(path, nodes, inputdata, configmanager)
    elif (path[:4] == ['configuration', 'management_controller',
            'net_interfaces', 'management'] and operation != 'retrieve'):
        return InputNetworkConfiguration(path, nodes, inputdata,
                                         configmanager)
    elif (path[:3] == ['configuration', 'management_controller', 'domain_name']
            and operation != 'retrieve'):
        return InputDomainName(path, nodes, inputdata)
    elif (path[:4] == ['configuration', 'management_controller', 'ntp',
            'enabled'] and operation != 'retrieve'):
        return InputNTPEnabled(path, nodes, inputdata)
    elif (path[:4] == ['configuration', 'management_controller', 'ntp',
            'servers'] and operation != 'retrieve' and len(path) == 5):
        return InputNTPServer(path, nodes, inputdata)
    elif (path[:3] in (['configuration', 'system', 'all'],
            ['configuration', 'management_controller', 'extended']) and
            operation != 'retrieve'):
        return InputConfigChangeSet(path, inputdata, nodes, configmanager)
    elif (path[0] == 'configuration' and path[2] == 'clear'  and
            operation != 'retrieve'):
        return InputConfigClear(path, inputdata, nodes, configmanager)
    elif (path[:3] == ['configuration', 'storage', 'disks'] and
            operation != 'retrieve'):
        return InputDisk(path, nodes, inputdata)
    elif (path[:3] == ['configuration', 'storage', 'volumes'] and
          operation in ('update', 'create')):
        return InputVolumes(path, nodes, inputdata)
    elif 'inventory/firmware/updates/active' in '/'.join(path) and inputdata:
        return InputFirmwareUpdate(path, nodes, inputdata, configmanager)
    elif ('/'.join(path).startswith('power/inlets/') or '/'.join(path).startswith('power/outlets/')) and inputdata:
        return InputPowerMessage(path, nodes, inputdata)
    elif '/'.join(path).startswith('media/detach'):
        return DetachMedia(path, nodes, inputdata)
    elif '/'.join(path).startswith('media/') and inputdata:
        return InputMedia(path, nodes, inputdata, configmanager)
    elif '/'.join(path).startswith('support/servicedata') and inputdata:
        return InputMedia(path, nodes, inputdata, configmanager)
    elif '/'.join(path).startswith('configuration/management_controller/save_licenses') and inputdata:
        return InputMedia(path, nodes, inputdata, configmanager)
    elif '/'.join(path).startswith(
            'configuration/management_controller/licenses') and inputdata:
        return InputLicense(path, nodes, inputdata, configmanager)
    elif path == ['deployment', 'ident_image']:
        return InputIdentImage(path, nodes, inputdata)
    elif path == ['console', 'ikvm']:
        return InputIkvmParams(path, nodes, inputdata)
    elif inputdata:
        raise exc.InvalidArgumentException(
            'No known input handler for request')

class InputFirmwareUpdate(ConfluentMessage):

    def __init__(self, path, nodes, inputdata, configmanager):
        self._filename = inputdata.get('filename', inputdata.get('url', inputdata.get('dirname', None)))
        self.bank = inputdata.get('bank', None)
        self.nodes = nodes
        self.filebynode = {}
        self._complexname = False
        for expanded in configmanager.expand_attrib_expression(
                nodes, self._filename):
            node, value = expanded
            if value != self._filename:
                self._complexname = True
            self.filebynode[node] = value

    @property
    def filename(self):
        # TODO: get the currennt_user and cross reference if that user is allowed to
        # read...  however, not sure wwhat to do if user is pure confluent user
        # though the staging may get an explicit pass, which should cover the web case...
        # media and firmware are ways to currently push things out, but if we allow profile export
        # what then?
        if self._complexname:
            raise Exception('User requested substitutions, but code is '
                            'written against old api, code must be fixed or '
                            'skip {} expansion')
        if self.filebynode[node].startswith('/etc/confluent'):
            raise Exception(
                'File transfer with /etc/confluent is not supported')
        if self.filebynode[node].startswith('/var/log/confluent'):
            raise Exception(
                'File transfer with /var/log/confluent is not supported')
        return self._filename

    def nodefile(self, node):
        if self.filebynode[node].startswith('/etc/confluent'):
            raise Exception(
                'File transfer with /etc/confluent is not supported')
        if self.filebynode[node].startswith('/var/log/confluent'):
            raise Exception(
                'File transfer with /var/log/confluent is not supported')
        return self.filebynode[node]

class InputMedia(InputFirmwareUpdate):
    # Use InputFirmwareUpdate
    pass

class InputLicense(InputFirmwareUpdate):
    pass


class DetachMedia(ConfluentMessage):
    def __init__(self, path, nodes, inputdata):
        if 'detachall' not in inputdata:
            raise exc.InvalidArgumentException('Currently only supporting'
                                               '{"detachall": 1}')


class Media(ConfluentMessage):
    def __init__(self, node, media=None, rawmedia=None):
        if media:
            rawmedia = {'name': media.name, 'url': media.url}
        self.myargs = (node, None, rawmedia)
        self.kvpairs = {node: rawmedia}

class SavedFile(ConfluentMessage):
    def __init__(self, node, file):
        self.myargs = (node, file)
        self.kvpairs = {node: {'filename': file}}

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


class InputExpression(ConfluentMessage):
    # This is specifically designed to suppress the expansion of an expression
    # so that it can make it intact to the pertinent configmanager function
    def __init__(self, path, inputdata, nodes=None):
        self.nodeattribs = {}
        if not inputdata:
            raise exc.InvalidArgumentException('no request data provided')
        if nodes is None:
            self.attribs = inputdata
            return
        for node in nodes:
            self.nodeattribs[node] = inputdata

    def get_attributes(self, node):
        if node not in self.nodeattribs:
            return {}
        nodeattr = deepcopy(self.nodeattribs[node])
        return nodeattr

class InputConfigClear(ConfluentMessage):
    def __init__(self, path, inputdata, nodes=None, configmanager=None):
        if not inputdata:
            raise exc.InvalidArgumentException('no request data provided')
        if 'clear' not in inputdata or not inputdata['clear']:
            raise exc.InvalidArgumentException('Input must be {"clear":true}')

class InputConfigChangeSet(InputExpression):
    def __init__(self, path, inputdata, nodes=None, configmanager=None):
        self.cfm = configmanager
        super(InputConfigChangeSet, self).__init__(path, inputdata, nodes)

    def get_attributes(self, node):
        attrs = super(InputConfigChangeSet, self).get_attributes(node)
        endattrs = {}
        for attr in attrs:
            origval = attrs[attr]
            if isinstance(origval, bytes) or isinstance(origval, unicode):
                origval = {'expression': origval}
            if 'expression' not in origval:
                endattrs[attr] = attrs[attr]
            else:
                endattrs[attr] = list(self.cfm.expand_attrib_expression(
                    [node], attrs[attr]))[0][1]
        return endattrs

class InputAttributes(ConfluentMessage):
    # This is particularly designed for attributes, where a simple string
    # should become either a string value or a dict with {'expression':} to
    # preserve the client provided expression for posterity, rather than
    # immediate consumption.
    # for things like node configuration or similar, a different class is
    # appropriate since it needs to immediately expand an expression.
    # with that class, the 'InputExpression' and calling code in attributes.py
    # might be deprecated in favor of the generic expression expander
    # and a small function in attributes.py to reflect the expansion back
    # to the client
    def __init__(self, path, inputdata, nodes=None):
        self.nodeattribs = {}
        if not inputdata:
            raise exc.InvalidArgumentException('no request data provided')
        if nodes is None:
            self.attribs = inputdata
            for attrib in self.attribs:
                if not cfm.attrib_supports_expression(attrib):
                    continue
                if type(self.attribs[attrib]) in (bytes, unicode):
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
            self.nodeattribs[node] = inputdata

    def get_attributes(self, node, validattrs=None):
        if node not in self.nodeattribs:
            return {}
        nodeattr = deepcopy(self.nodeattribs[node])
        for attr in nodeattr:
            if type(nodeattr[attr]) in (bytes, unicode) and cfm.attrib_supports_expression(attr):
                try:
                    # as above, use format() to see if string follows
                    # expression, store value back in case of escapes
                    tv = nodeattr[attr].format()
                    nodeattr[attr] = str(tv)
                except (KeyError, IndexError):
                    # an expression string will error if format() done
                    # use that as cue to put it into config as an expr
                    nodeattr[attr] = {'expression': nodeattr[attr]}
            if validattrs and 'validvalues' in validattrs.get(attr, []):
                if (nodeattr[attr] and
                        nodeattr[attr] not in validattrs[attr]['validvalues']):
                    raise exc.InvalidArgumentException(
                        'Attribute {0} does not accept value {1} (valid values would be {2})'.format(
                            attr, nodeattr[attr], ','.join(validattrs[attr]['validvalues'])))
            elif validattrs and 'validlist' in validattrs.get(attr, []) and nodeattr[attr]:
                req = nodeattr[attr].split(',')
                for v in req:
                    if v and v not in validattrs[attr]['validlist']:
                        raise exc.InvalidArgumentException(
                            'Attribute {0} does not accept list member '
                            '{1} (valid values would be {2})'.format(
                                attr, v, ','.join(
                                    validattrs[attr]['validlist'])))
            elif validattrs and 'validlistkeys' in validattrs.get(attr, []) and nodeattr[attr]:
                req = nodeattr[attr].split(',')
                for v in req:
                    if '=' not in v:
                        raise exc.InvalidArgumentException(
                            'Passed key {0} requires a parameter'.format(v))
                    v = v.split('=', 1)[0]
                    if v and v not in validattrs[attr]['validlistkeys']:
                        raise exc.InvalidArgumentException(
                            'Attribute {0} does not accept key {1} (valid values would be {2})'.format(
                                attr, v, ','.join(
                                    validattrs[attr]['validlistkeys'])
                            )
                        )
        return nodeattr

def checkPassword(password, username):
    lowercase = set('abcdefghijklmnopqrstuvwxyz')
    uppercase = set('abcdefghijklmnopqrstuvwxyz'.upper())
    numbers = set('0123456789')
    special = set('`~!@#$%^&*()-_=+[{]};:"/?.>,<' + "'")
    if len(password) < passminlength:
        raise exc.InvalidArgumentException('Password must be at least {0} characters long'.format(passminlength))
    if not isinstance(passcomplexity, int) or passcomplexity < 1:
        return
    if not bool(set(password.lower()) & lowercase):  # rule 1
        raise exc.InvalidArgumentException('Password must contain at least one letter')
    if passcomplexity < 2:
        return
    thepass = set(password)
    if not bool(thepass & numbers):  # rule 2
        raise exc.InvalidArgumentException('Password must contain at least one number')
    if passcomplexity < 3:
        return
    classes = 0
    for charclass in (lowercase, uppercase, special):
        if bool(thepass & charclass):
            classes += 1
    if classes < 2:
        raise exc.InvalidArgumentException('Password must contain at least two of upper case letter, lower case letter, and/or special character')
    if passcomplexity < 4:
        return
    if username and password in (username, username[::-1]): # rule 4
        raise exc.InvalidArgumentException('Password must not be similar to username')
    if passcomplexity < 5:
        return
    for char in thepass:
        if char * 3 in password:
            raise exc.InvalidArgumentException('Password must not contain any of the same character repeated 3 times')



class InputCredential(ConfluentMessage):
    valid_privilege_levels = set([
        'callback',
        'user',
        'ReadOnly',
        'operator',
        'Operator',
        'administrator',
        'Administrator',
        'proprietary',
        'no_access',
    ])

    valid_enabled_values = set([
        'yes',
        'no'
    ])

    def __init__(self, path, inputdata, nodes=None):
        self.credentials = {}
        if not inputdata:
            raise exc.InvalidArgumentException('no request data provided')

        if len(path) == 4:
            inputdata['uid'] = path[-1]
        # if the operation is 'create' check if all fields are present
        if (type(inputdata['uid']) in (bytes, unicode) and
                not inputdata['uid'].isdigit()):
            inputdata['uid'] = inputdata['uid']
        else:
            inputdata['uid'] = int(inputdata['uid'])
        if ('privilege_level' in inputdata and
              inputdata['privilege_level'] not in self.valid_privilege_levels):
            if not inputdata['privilege_level'].startswith('custom.'):
                raise exc.InvalidArgumentException('privilege_level is not one of '
                                            + ','.join(self.valid_privilege_levels))
        if ('enabled' in inputdata and
            inputdata['enabled'] not in self.valid_enabled_values):
            raise exc.InvalidArgumentException('valid values for enabled are '
                                                            + 'yes and no')
        if 'password' in inputdata and (passcomplexity or passminlength):
            checkPassword(inputdata['password'], inputdata.get('username', None))
        if nodes is None:
            raise exc.InvalidArgumentException(
                'This only supports per-node input')
        for node in nodes:
            self.credentials[node] = inputdata

    def get_attributes(self, node):
        if node not in self.credentials:
            return {}
        credential = deepcopy(self.credentials[node])
        for attr in credential:
            if type(credential[attr]) in (bytes, unicode):
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
                elif not self.is_valid_key(datum[self.keyname]):
                    raise exc.InvalidArgumentException(
                        datum[self.keyname] + ' is not one of ' +
                        ','.join(self.valid_values))
                self.inputbynode[key] = datum[self.keyname]
        else:  # we have a state argument not by node
            datum = inputdata
            if self.keyname not in datum:
                raise exc.InvalidArgumentException(
                    'missing {0} argument'.format(self.keyname))
            elif not self.is_valid_key(datum[self.keyname]):
                raise exc.InvalidArgumentException(datum[self.keyname] +
                                                   ' is not one of ' +
                                                   ','.join(self.valid_values))
            for node in nodes:
                self.inputbynode[node] = datum[self.keyname]

    def is_valid_key(self, key):
        return key in self.valid_values


class InputIdentImage(ConfluentInputMessage):
    keyname = 'ident_image'
    valid_values = ['create']

class InputIkvmParams(ConfluentInputMessage):
    keyname = 'method'
    valid_values = ['unix', 'wss']

class InputIdentifyMessage(ConfluentInputMessage):
    valid_values = set([
        'on',
        'off',
        'blink',
    ])

    keyname = 'identify'


class InputDisk(ConfluentInputMessage):
    valid_values = set([
        'jbod',
        'unconfigured',
        'hotspare',
    ])

    keyname = 'state'


class InputVolumes(ConfluentInputMessage):
    def __init__(self, path, nodes, inputdata):
        self.inputbynode = {}
        self.stripped = False
        if not inputdata:
            raise exc.InvalidArgumentException('missing input data')
        if isinstance(inputdata, dict):
            volnames = [None]
            if len(path) == 6:
                volnames = path[-1]
            volnames = inputdata.get('name', volnames)
            if not isinstance(volnames, list):
                volnames = volnames.split(',')
            sizes = inputdata.get('size', [None])
            if not isinstance(sizes, list):
                sizes = sizes.split(',')
            stripsizes = inputdata.get('stripsizes', [None])
            if not isinstance(stripsizes, list):
                stripsizes = stripsizes.split(',')
            disks = inputdata.get('disks', [])
            if not disks:
                raise exc.InvalidArgumentException(
                    'disks are currently required to create a volume')
            raidlvl = inputdata.get('raidlevel', None)
            inputdata = []
            for size in sizes:
                if volnames:
                    currname = volnames.pop(0)
                else:
                    currname = None
                if stripsizes:
                    currstripsize = stripsizes.pop(0)
                    if currstripsize:
                        currstripsize = int(currstripsize)
                else:
                    currstripsize = None
                inputdata.append(
                    {'name': currname, 'size': size,
                     'stripsize': currstripsize,
                     'disks': disks,
                     'raidlevel': raidlvl})
        for node in nodes:
            self.inputbynode[node] = []
        for input in inputdata:
            volname = None
            if len(path) == 6:
                volname = path[-1]
            volname = input.get('name', volname)
            if not volname:
                volname = None
            volsize = input.get('size', None)
            if isinstance(input['disks'], list):
                disks = input['disks']
            else:
                disks = input['disks'].split(',')
            raidlvl = input.get('raidlevel', None)
            for node in nodes:
                self.inputbynode[node].append({'name': volname,
                                               'size': volsize,
                                               'disks': disks,
                                               'stripsize': input.get('stripsize', None),
                                               'raidlevel': raidlvl,
                                               })


class InputPowerMessage(ConfluentInputMessage):
    valid_values = set([
        'on',
        'off',
        'reset',
        'boot',
        'diag',
        'shutdown',
    ])

    def powerstate(self, node):
        return self.inputbynode[node]

class InputReseatMessage(ConfluentInputMessage):
    valid_values = set([
        'reseat',
    ])

    keyname = 'reseat'

    def is_valid_key(self, key):
        return key in self.valid_values or isinstance(key, int)


class InputBMCReset(ConfluentInputMessage):
    valid_values = set([
        'reset',
    ])

    def state(self, node):
        return self.inputbynode[node]



class InputHostname(ConfluentInputMessage):
    def __init__(self, path, nodes, inputdata, configmanager):
        self.inputbynode = {}
        self.stripped = False
        if not inputdata or 'hostname' not in inputdata:
            raise exc.InvalidArgumentException('missing hostname attribute')
        if nodes is None:
            raise exc.InvalidArgumentException(
                'This only supports per-node input')
        for expanded in configmanager.expand_attrib_expression(
                nodes, inputdata['hostname']):
            node, value = expanded
            self.inputbynode[node] = value

    def hostname(self, node):
        return self.inputbynode[node]


class InputMCI(ConfluentInputMessage):
    def __init__(self, path, nodes, inputdata):
        self.inputbynode = {}
        self.stripped = False
        if not inputdata or 'identifier' not in inputdata:
            raise exc.InvalidArgumentException('missing input data')
        if len(inputdata['identifier']) > 64:
            raise exc.InvalidArgumentException(
                'identifier must be less than or = 64 chars')

        if nodes is None:
            raise exc.InvalidArgumentException(
                'This only supports per-node input')
        for node in nodes:
            self.inputbynode[node] = inputdata

    def mci(self, node):
        return self.inputbynode[node]['identifier']


class InputNetworkConfiguration(ConfluentInputMessage):
    def __init__(self, path, nodes, inputdata, configmanager=None):
        self.inputbynode = {}
        self.stripped = False
        if not inputdata:
            raise exc.InvalidArgumentException('missing input data')

        if 'hw_addr' in inputdata:
            raise exc.InvalidArgumentException('hw_addr is a read only field')

        if 'ipv4_address' not in inputdata:
            inputdata['ipv4_address'] = None

        if 'ipv4_gateway' not in inputdata:
            inputdata['ipv4_gateway'] = None

        if 'ipv4_configuration' in inputdata and inputdata['ipv4_configuration']:
            if inputdata['ipv4_configuration'].lower() not in ['dhcp','static']:
                raise exc.InvalidArgumentException(
                                            'Unrecognized ipv4_configuration')
        else:
            inputdata['ipv4_configuration'] = None
        if nodes is None:
            raise exc.InvalidArgumentException(
                'This only supports per-node input')
        nodeattrmap = {}
        for attr in inputdata:
            try:
                if inputdata[attr] is not None:
                    inputdata[attr].format()
            except (KeyError, IndexError):
                nodeattrmap[attr] = {}
                for expanded in configmanager.expand_attrib_expression(
                        nodes, inputdata[attr]):
                    node, value = expanded
                    nodeattrmap[attr][node] = value
        if not nodeattrmap:
            for node in nodes:
                self.inputbynode[node] = inputdata
            return
        # an expression was encountered
        for node in nodes:
            self.inputbynode[node] = deepcopy(inputdata)
            for attr in self.inputbynode[node]:
                if attr in nodeattrmap:
                    self.inputbynode[node][attr] = nodeattrmap[attr][node]

    def netconfig(self, node):
        return self.inputbynode[node]


class InputDomainName(ConfluentInputMessage):
    def __init__(self, path, nodes, inputdata):
        self.inputbynode = {}
        self.stripped = False
        if not inputdata or 'domain_name' not in inputdata:
            raise exc.InvalidArgumentException('missing input data')
        if len(inputdata['domain_name']) > 256:
            raise exc.InvalidArgumentException(
                'identifier must be less than or = 256 chars')

        if nodes is None:
            raise exc.InvalidArgumentException(
                'This only supports per-node input')
        for node in nodes:
            self.inputbynode[node] = inputdata['domain_name']

    def domain_name(self, node):
        return self.inputbynode[node]


class InputNTPServer(ConfluentInputMessage):
    def __init__(self, path, nodes, inputdata):
        self.inputbynode = {}
        self.stripped = False
        if not inputdata or 'server' not in inputdata:
            raise exc.InvalidArgumentException('missing input data')
        if len(inputdata['server']) > 256:
            raise exc.InvalidArgumentException(
                'identifier must be less than or = 256 chars')

        if nodes is None:
            raise exc.InvalidArgumentException(
                'This only supports per-node input')
        for node in nodes:
            self.inputbynode[node] = str(inputdata['server'])

    def ntp_server(self, node):
        return self.inputbynode[node]


class InputNTPEnabled(ConfluentInputMessage):
    valid_values = set([
        'True',
        'False'
    ])

    def ntp_enabled(self, node):
        return self.inputbynode[node]


class BootDevice(ConfluentChoiceMessage):
    valid_values = set([
        'network',
        'hd',
        'setup',
        'default',
        'cd',
        'floppy',
        'usb',
    ])

    valid_bootmodes = set([
        'unspecified',
        'bios',
        'uefi',
    ])

    valid_paramset = {
        'bootmode': valid_bootmodes,
        'persistent': set([True, False]),
        }

    def __init__(self, node, device, bootmode='unspecified', persistent=False):
        self.myargs = (node, device, bootmode, persistent)
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
                'persistent': {'value': persistent},
            }
        }


class InputBootDevice(BootDevice):
    def __init__(self, path, nodes, inputdata):
        self.bootdevbynode = {}
        self.bootmodebynode = {}
        self.persistentbynode = {}
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
                if 'persistent' in datum:
                    self.bootmodebynode[key] = datum['persistent']
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
                if 'persistent' in datum:
                    self.persistentbynode[node] = datum['persistent']

    def bootdevice(self, node):
        return self.bootdevbynode[node]

    def bootmode(self, node):
        return self.bootmodebynode.get(node, 'unspecified')

    def persistent(self, node):
        return self.persistentbynode.get(node, False)


class IdentifyState(ConfluentChoiceMessage):
    valid_values = set([
        '',  # allowed for output to indicate write-only support
        'on',
        'off',
    ])
    keyname = 'identify'


class ReseatResult(ConfluentChoiceMessage):
    valid_values = set([
        'success',
    ])
    keyname = 'reseat'


class PowerState(ConfluentChoiceMessage):
    valid_values = set([
        'on',
        'off',
        'reset',
        'boot',
        'shutdown',
        'diag',
    ])
    keyname = 'state'

    def __init__(self, node, state, oldstate=None):
        super(PowerState, self).__init__(node, state)
        self.myargs = (node, state, oldstate)
        if oldstate is not None:
            self.kvpairs[node]['oldstate'] = {'value': oldstate}

class BMCReset(ConfluentChoiceMessage):
    valid_values = set([
        'reset',
    ])
    keyname = 'state'


class NTPEnabled(ConfluentChoiceMessage):
    valid_values = set([
        'True',
        'False',
    ])

    def __init__(self, node, enabled):
        self.stripped = False
        self.myargs = (node, enabled)
        self.kvpairs = {
            node: {
                'state': {'value': str(enabled)},
            }
        }

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
        self.myname = name
        self.myargs = (eventdata, name)
        for event in events:
            entry = {
                'id': event.get('id', None),
                'component': event.get('component', None),
                'component_type': event.get('component_type', None),
                'event': event.get('event', None),
                'severity': event['severity'],
                'timestamp': event.get('timestamp', None),
                'message': event.get('message', None),
                'record_id': event.get('record_id', None),
                'log_id': event.get('log_id', None),
            }
            if event['severity'] not in valid_health_values:
                raise exc.NotImplementedException(
                    'Invalid severity - ' + repr(event['severity']))
            eventdata.append(entry)
        if self.notnode:
            self.kvpairs = {'events': eventdata}
        else:
            self.kvpairs = {name: {'events': eventdata}}


class AsyncCompletion(ConfluentMessage):
    def __init__(self):
        self.stripped = True
        self.notnode = True

    @classmethod
    def deserialize(cls):
        raise Exception("Not supported")

    def raw(self):
        return {'_requestdone': True}


class AsyncMessage(ConfluentMessage):
    def __init__(self, pair):
        self.stripped = True
        self.notnode = True
        self.msgpair = pair

    @classmethod
    def deserialize(cls):
        raise Exception("Not supported")

    def raw(self):
        rsp = self.msgpair[1]
        rspdict = None
        if (isinstance(rsp, ConfluentMessage) or
                isinstance(rsp, ConfluentNodeError)):
            rspdict = rsp.raw()
        elif isinstance(rsp, exc.ConfluentException):
            rspdict = {'exceptioncode': rsp.apierrorcode,
                       'exception': rsp.get_error_body()}
        elif isinstance(rsp, Exception):
            rspdict = {'exceptioncode': 500, 'exception': str(rsp)}
        elif isinstance(rsp, dict):  # console metadata
            rspdict = rsp
        else: # terminal text
            rspdict = {'data': rsp}
        return {'asyncresponse':
                    {'requestid': self.msgpair[0],
                      'response': rspdict}}

class AsyncSession(ConfluentMessage):
    def __init__(self, id):
        self.desc = 'foo'
        self.notnode = True
        self.stripped = True
        self.kvpairs = {'asyncid': id}

class User(ConfluentMessage):
    def __init__(self, uid, username, privilege_level, name=None, expiration=None):
        self.desc = 'foo'
        self.stripped = False
        self.notnode = name is None
        self.myargs = (uid, username, privilege_level, name, expiration)
        kvpairs = {'username': {'value': username},
                   'password': {'value': '', 'type': 'password'},
                   'privilege_level': {'value': privilege_level},
                   'enabled': {'value': ''},
                   'expiration': {'value': expiration},
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
        self.myargs = (userlist, name)
        for user in users:
            if 'username' in user:  # processing an already translated dict
                userlist.append(user)
                continue
            entry = {
                'uid': user['uid'],
                'username': user['name'],
                'expiration': user.get('expiration', None),
                'privilege_level': user['access']['privilege_level']
            }
            userlist.append(entry)
        if self.notnode:
            self.kvpairs = {'users': userlist}
        else:
            self.kvpairs = {name: {'users': userlist}}



class AlertDestination(ConfluentMessage):
    def __init__(self, ip, acknowledge=False, acknowledge_timeout=None, retries=0, name=None):
        self.myargs = (ip, acknowledge, acknowledge_timeout, retries, name)
        self.desc = 'foo'
        self.stripped = False
        self.notnode = name is None
        kvpairs = {'ip': {'value': ip},
                   'acknowledge': {'value': acknowledge},
                   'acknowledge_timeout': {'value': acknowledge_timeout},
                   'retries': {'value': retries}}
        if self.notnode:
            self.kvpairs = kvpairs
        else:
            self.kvpairs = {name: kvpairs}


class InputAlertDestination(ConfluentMessage):
    valid_alert_params = {
        'acknowledge': lambda x: False if type(x) in (unicode, bytes) and x.lower() == 'false' else bool(x),
        'acknowledge_timeout': lambda x: int(x) if x and x.isdigit() else None,
        'ip': lambda x: x,
        'retries': lambda x: int(x)
    }

    def __init__(self, path, nodes, inputdata, multinode=False):
        self.alertcfg = {}
        if multinode:  # keys are node names
            for node in inputdata:
                if not isinstance(inputdata[node], dict):
                    break
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
                return
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
        self.myargs = (readings, name)
        for sensor in sensors:
            if isinstance(sensor, dict):
                readings.append(sensor)
                continue
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
        for datum in data:
            for component in datum:
                for field in datum[component]:
                    tdatum = datum[component]
                    if isinstance(tdatum[field], datetime):
                        tdatum[field] = tdatum[field].strftime('%Y-%m-%dT%H:%M:%S')
        self.myargs = (data, name)
        self.notnode = name is None
        self.desc = 'Firmware information'
        if self.notnode:
            self.kvpairs = {'firmware': data}
        else:
            self.kvpairs = {name:  {'firmware': data}}


class KeyValueData(ConfluentMessage):
    readonly = True

    def __init__(self, kvdata, name=None):
        self.myargs = (kvdata, name)
        self.notnode = name is None
        if self.notnode:
            self.kvpairs = kvdata
        else:
            self.kvpairs = {name: kvdata}

class Array(ConfluentMessage):
    def __init__(self, name, disks=None, raid=None, volumes=None,
                 id=None, capacity=None, available=None):
        self.myargs = (name, disks, raid, volumes, id, capacity, available)
        self.kvpairs = {
            name: {
                'type': 'array',
                'disks': disks,
                'raid': raid,
                'id': id,
                'volumes': volumes,
                'capacity': capacity,
                'available': available,
            }
        }

class Volume(ConfluentMessage):
    def __init__(self, name, volname, size, state, array, stripsize=None):
        self.myargs = (name, volname, size, state, array, stripsize)
        self.kvpairs = {
            name: {
                'type': 'volume',
                'name': simplify_name(volname),
                'label': volname,
                'stripsize': stripsize,
                'size': size,
                'state': state,
                'array': array,
            }
        }

class Disk(ConfluentMessage):
    valid_states = set([
        'fault',
        'jbod',
        'unconfigured',
        'hotspare',
        'rebuilding',
        'online',
        'offline',
    ])
    state_aliases = {
        'unconfigured bad': 'fault',
        'unconfigured good': 'unconfigured',
        'global hot spare': 'hotspare',
        'dedicated hot spare': 'hotspare',
    }

    def _normalize_state(self, instate):
        newstate = instate.lower()
        if newstate in self.valid_states:
            return newstate
        elif newstate in self.state_aliases:
            return self.state_aliases[newstate]
        raise Exception("Unknown state {0}".format(instate))


    def __init__(self, name, label=None, description=None,
                 diskid=None, state=None, serial=None, fru=None,
                 array=None):
        self.myargs = (name, label, description, diskid, state,
                       serial, fru, array)
        state = self._normalize_state(state)
        self.kvpairs = {
            name: {
                'type': 'disk',
                'name': simplify_name(label),
                'label': label,
                'description': description,
                'diskid': diskid,
                'state': state,
                'serial': serial,
                'fru': fru,
                'array': array,
            }
        }



class LEDStatus(ConfluentMessage):
    readonly = True

    def __init__(self, data, name):
        self.myargs = (data, name)
        self.notnode = name is None
        self.desc = 'led status'

        if self.notnode:
            self.kvpairs = {'leds':data}
        else:
            self.kvpairs = {name: {'leds':data}}


class NetworkConfiguration(ConfluentMessage):
    desc = 'Network configuration'

    def __init__(self, name=None, ipv4addr=None, ipv4gateway=None,
                 ipv4cfgmethod=None, hwaddr=None, staticv6addrs=(), staticv6gateway=None):
        self.myargs = (name, ipv4addr, ipv4gateway, ipv4cfgmethod, hwaddr)
        self.notnode = name is None
        self.stripped = False
        v6addrs = ','.join(staticv6addrs)

        kvpairs = {
            'ipv4_address': {'value': ipv4addr},
            'ipv4_gateway': {'value': ipv4gateway},
            'ipv4_configuration': {'value': ipv4cfgmethod},
            'hw_addr': {'value': hwaddr},
            'static_v6_addresses': {'value': v6addrs},
            'static_v6_gateway': {'value': staticv6gateway}
        }
        if self.notnode:
            self.kvpairs = kvpairs
        else:
            self.kvpairs = {name: kvpairs}


class HealthSummary(ConfluentMessage):
    readonly = True
    valid_values = valid_health_values

    def __init__(self, health, name=None):
        self.myargs = (health, name)
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
        self.myargs = (name, kv, desc)
        self.desc = desc
        nkv = {}
        self.notnode = name is None
        for key in kv:
            if type(kv[key]) in (bytes, unicode):
                nkv[key] = {'value': kv[key]}
            else:
                nkv[key] = kv[key]
        if self.notnode:
            self.kvpairs = nkv
        else:
            self.kvpairs = {
                name: nkv
            }

class ConfigSet(Attributes):
    pass

class ListAttributes(ConfluentMessage):
    def __init__(self, name=None, kv=None, desc=''):
        self.myargs = (name, kv, desc)
        self.desc = desc
        self.notnode = name is None
        if self.notnode:
            self.kvpairs = kv
        else:
            self.kvpairs = {name: kv}


class MCI(ConfluentMessage):
    def __init__(self, name=None, mci=None):
        self.myargs = (name, mci)
        self.notnode = name is None
        self.desc = 'BMC identifier'

        kv = {'identifier': {'value': mci}}
        if self.notnode:
            self.kvpairs = kv
        else:
            self.kvpairs = {name: kv}


class Hostname(ConfluentMessage):
    def __init__(self, name=None, hostname=None):
        self.myargs = (name, hostname)
        self.notnode = name is None
        self.desc = 'BMC hostname'

        kv = {'hostname': {'value': hostname}}
        if self.notnode:
            self.kvpairs = kv
        else:
            self.kvpairs = {name: kv}

class DomainName(ConfluentMessage):
    def __init__(self, name=None, dn=None):
        self.myargs = (name, dn)
        self.notnode = name is None
        self.desc = 'BMC domain name'

        kv = {'domain_name': {'value': dn}}
        if self.notnode:
            self.kvpairs = kv
        else:
            self.kvpairs = {name: kv}


class NTPServers(ConfluentMessage):
    readonly = True

    def __init__(self, name=None, servers=None):
        self.myargs = (name, servers)
        self.notnode = name is None
        self.desc = 'NTP Server'

        kv = []
        for idx in range(0, len(servers)):
            kv.append({str(idx+1): servers[idx]})
        if self.notnode:
            self.kvpairs = {'ntp_servers': kv}
        else:
            self.kvpairs = {name: {'ntp_servers': kv}}


class NTPServer(ConfluentMessage):
    def __init__(self, name=None, server=None):
        self.myargs = (name, server)
        self.notnode = name is None
        self.desc = 'NTP Server'

        kv = {
            'server': {'value': server},
        }
        if self.notnode:
            self.kvpairs = kv
        else:
            self.kvpairs = {name: kv}


class License(ConfluentMessage):
    readonly = True

    def __init__(self, name=None, kvm=None, feature=None, state=None):
        self.myargs = (name, kvm, feature, state)
        self.notnode = name is None
        self.desc = 'License'

        kv = []
        kv.append({'kvm_availability': str(kvm), 'feature': feature, 'state': state})
        if self.notnode:
            self.kvpairs = {'License': kv}
        else:
            self.kvpairs = {name: {'License': kv}}

class GraphicalConsole(ConfluentMessage):
    readonly = True

    def __init__(self, name=None, mime=None, data=None):
        self.notnode = name is None
        self.desc = 'Graphical console launcher'

        kv = []
        kv.append({'mime': mime, 'data': data})
        if self.notnode:
            self.kvpairs = {'Launcher': kv}
        else:
            self.kvpairs = {name: {'Launcher': kv}}

class CryptedAttributes(Attributes):
    defaulttype = 'password'

    def __init__(self, name=None, kv=None, desc=''):
        self.myargs = (name, kv, desc)
        # for now, just keep the dictionary keys and discard crypt value
        self.desc = desc
        nkv = {}
        for key in kv:
            nkv[key] = {'isset': False}
            if kv[key] and 'hashvalue' in kv[key]:
                targkey = 'hashvalue'
            else:
                targkey = 'cryptvalue'
            try:
                if kv[key] is not None and kv[key][targkey] != '':
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
