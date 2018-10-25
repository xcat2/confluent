# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 IBM Corporation
# Copyright 2015-2017 Lenovo
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
from copy import deepcopy
from datetime import datetime
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
        for key in sorted(indict):
            ret += "<li>{0}: ".format(key)
            if type(indict[key]) in (str, unicode, float, int):
                ret += str(indict[key])
            elif isinstance(indict[key], datetime):
                ret += indict[key].strftime('%Y-%m-%dT%H:%M:%S')
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
            if (isinstance(val, bool) or isinstance(val, str) or
                    isinstance(val, unicode)):
                value = str(val)
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

    def raw(self):
        return {'databynode': {self.node: {'errorcode': self.apicode,
                                           'error': self.error}}}

    def html(self):
        return self.node + ":" + self.error

    def strip_node(self, node):
        # NOTE(jjohnson2): For single node errors, raise exception to
        # trigger what a developer of that medium would expect
        raise Exception(self.error)


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
    def __init__(self, node):
        self.node = node
        self.error = 'bad credentials'

    def strip_node(self, node):
        raise exc.TargetEndpointBadCredentials


class DeletedResource(ConfluentMessage):
    notnode = True
    def __init__(self, resource):
        self.kvpairs = {'deleted': resource}

    def strip_node(self, node):
        pass


class CreatedResource(ConfluentMessage):
    notnode = True
    readonly = True

    def __init__(self, resource):
        self.kvpairs = {'created': resource}

    def strip_node(self, node):
        pass


class AssignedResource(ConfluentMessage):
    notnode = True
    readonly = True

    def __init__(self, resource):
        self.kvpairs = {'assigned': resource}

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
    elif (path[:3] == ['configuration', 'system', 'all'] and
            operation != 'retrieve'):
        return InputConfigChangeSet(path, inputdata, nodes, configmanager)
    elif (path[:3] == ['configuration', 'system', 'clear'] and
            operation != 'retrieve'):
        return InputConfigClear(path, inputdata, nodes, configmanager)
    elif (path[:3] == ['configuration', 'storage', 'disks'] and
            operation != 'retrieve'):
        return InputDisk(path, nodes, inputdata)
    elif 'inventory/firmware/updates/active' in '/'.join(path) and inputdata:
        return InputFirmwareUpdate(path, nodes, inputdata)
    elif '/'.join(path).startswith('media/detach'):
        return DetachMedia(path, nodes, inputdata)
    elif '/'.join(path).startswith('media/') and inputdata:
        return InputMedia(path, nodes, inputdata)
    elif '/'.join(path).startswith('support/servicedata') and inputdata:
        return InputMedia(path, nodes, inputdata)
    elif inputdata:
        raise exc.InvalidArgumentException(
            'No known input handler for request')

class InputFirmwareUpdate(ConfluentMessage):

    def __init__(self, path, nodes, inputdata):
        self.filename = inputdata.get('filename', inputdata.get('url', None))
        self.bank = inputdata.get('bank', None)
        self.nodes = nodes

class InputMedia(InputFirmwareUpdate):
    # Use InputFirmwareUpdate
    pass


class DetachMedia(ConfluentMessage):
    def __init__(self, path, nodes, inputdata):
        if 'detachall' not in inputdata:
            raise exc.InvalidArgumentException('Currently only supporting'
                                               '{"detachall": 1}')


class Media(ConfluentMessage):
    def __init__(self, node, media):
        self.kvpairs = {node: {'name': media.name, 'url': media.url}}

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
    # For now, this is identical to InputExpression, later it may
    # internalize formula expansion, but not now..
    def __init__(self, path, inputdata, nodes=None, configmanager=None):
        self.cfm = configmanager
        super(InputConfigChangeSet, self).__init__(path, inputdata, nodes)

    def get_attributes(self, node):
        attrs = super(InputConfigChangeSet, self).get_attributes(node)
        endattrs = {}
        for attr in attrs:
            origval = attrs[attr]
            if isinstance(origval, str) or isinstance(origval, unicode):
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
            self.nodeattribs[node] = inputdata

    def get_attributes(self, node):
        if node not in self.nodeattribs:
            return {}
        nodeattr = deepcopy(self.nodeattribs[node])
        for attr in nodeattr:
            if type(nodeattr[attr]) in (str, unicode):
                try:
                    # as above, use format() to see if string follows
                    # expression, store value back in case of escapes
                    tv = nodeattr[attr].format()
                    nodeattr[attr] = str(tv)
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
        if not inputdata:
            raise exc.InvalidArgumentException('no request data provided')

        if len(path) == 4:
            inputdata['uid'] = path[-1]
        # if the operation is 'create' check if all fields are present
        missingattrs = []
        for attrname in ('uid', 'privilege_level', 'username', 'password'):
            if attrname not in inputdata:
                missingattrs.append(attrname)
        if missingattrs:
            raise exc.InvalidArgumentException(
                'Required fields missing: {0}'.format(','.join(missingattrs)))
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
        credential = deepcopy(self.credentials[node])
        for attr in credential:
            if type(credential[attr]) in (str, unicode):
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

class InputIdentifyMessage(ConfluentInputMessage):
    valid_values = set([
        'on',
        'off',
    ])

    keyname = 'identify'


class InputDisk(ConfluentInputMessage):
    valid_values = set([
        'jbod',
        'unconfigured',
        'hotspare',
    ])

    keyname = 'state'


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

        if 'ipv4_configuration' in inputdata:
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


class AsyncCompletion(ConfluentMessage):
    def __init__(self):
        self.stripped = True
        self.notnode = True

    def raw(self):
        return {'_requestdone': True}


class AsyncMessage(ConfluentMessage):
    def __init__(self, pair):
        self.stripped = True
        self.notnode = True
        self.msgpair = pair

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
    def __init__(self, ip, acknowledge=False, acknowledge_timeout=None, retries=0, name=None):
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
        'acknowledge': lambda x: False if type(x) in (unicode,str) and x.lower() == 'false' else bool(x),
        'acknowledge_timeout': lambda x: int(x) if x and x.isdigit() else None,
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

class Disk(ConfluentMessage):
    valid_states = set([
        'jbod',
        'unconfigured',
        'hotspare',
    ])
    state_aliases = {
        'unconfigured good': 'unconfigured',
        'global hot spare': 'hotspare',
    }

    def _normalize_state(self, instate):
        newstate = instate.lower()
        if newstate in self.valid_states:
            return newstate
        elif newstate in self.state_aliases:
            return self.state_aliases[newstate]
        raise Exception("Unknown state {0}".format(instate))


    def __init__(self, name, label=None, description=None,
                 diskid=None, state=None, serial=None, fru=None):
        state = self._normalize_state(state)
        self.kvpairs = {
            name: {
                'label': label,
                'description': description,
                'diskid': diskid,
                'state': state,
                'serial': serial,
                'fru': fru,
            }
        }



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
        for key in kv:
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

class ConfigSet(Attributes):
    pass

class ListAttributes(ConfluentMessage):
    def __init__(self, name=None, kv=None, desc=''):
        self.desc = desc
        self.notnode = name is None
        if self.notnode:
            self.kvpairs = kv
        else:
            self.kvpairs = {name: kv}


class MCI(ConfluentMessage):
    def __init__(self, name=None, mci=None):
        self.notnode = name is None
        self.desc = 'BMC identifier'

        kv = {'identifier': {'value': mci}}
        if self.notnode:
            self.kvpairs = kv
        else:
            self.kvpairs = {name: kv}


class Hostname(ConfluentMessage):
    def __init__(self, name=None, hostname=None):
        self.notnode = name is None
        self.desc = 'BMC hostname'

        kv = {'hostname': {'value': hostname}}
        if self.notnode:
            self.kvpairs = kv
        else:
            self.kvpairs = {name: kv}

class DomainName(ConfluentMessage):
    def __init__(self, name=None, dn=None):
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

    def __init__(self, name=None, kvm=None):
        self.notnode = name is None
        self.desc = 'License'

        kv = []
        kv.append({'kvm_availability': str(kvm)})
        if self.notnode:
            self.kvpairs = {'License': kv}
        else:
            self.kvpairs = {name: {'License': kv}}


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
