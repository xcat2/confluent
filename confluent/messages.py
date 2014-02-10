#Copyright 2013 IBM All rights reserved

# This module implements client/server messages emitted from plugins.
# Things are defined here to 'encourage' developers to coordinate information
# format.  This is also how different data formats are supported
import confluent.exceptions as exc
import json


class ConfluentMessage(object):
    defaultvalue = ''
    defaulttype = 'text'

    def __init__(self):
        raise NotImplementedError("Must be subclassed!")

    def json(self):
        # This will create the canonical json representation of this message
        jsonsnippet = json.dumps(self.kvpairs, separators=(',', ':'))[1:-1]
        return jsonsnippet

    def rawdata(self):
        """Return pythonic representation of the response.

        Used by httpapi while assembling data prior to json serialization"""
        return self.kvpairs

    def strip_node(self, node):
        self.kvpairs = self.kvpairs[node]

    def html(self):
        #this is used to facilitate the api explorer feature
        snippet = ""
        for key in self.kvpairs.iterkeys():
            val = self.kvpairs[key]
            value = self.defaultvalue
            note = ''
            type = self.defaulttype
            try:
                desc = self.desc
            except:
                desc = ''
            if 'value' in val:
                value = val['value']
            if value is None:
                value = ''
            if 'note' in val:
                note = '(' + val['note'] + ')'
            if isinstance(val, list):
                snippet += key + ":"
                for v in val:
                    snippet += ('<input type="{0}" name="{1}" value="{2}" '
                                ' "title="{3}">{4}'
                                ).format(type, key, v, desc, note)
                snippet += (
                    '<input type="{0}" name="{1}" value="" title="{2}">{3}'
                    '<input type="checkbox" name="restexplorerhonorkey" '
                    'value="{1}">').format(type, key, desc, note)
                return snippet
            snippet += (key + ":" +
                        '<input type="{0}" name="{1}" value="{2}" '
                        'title="{3}">{4}<input type="checkbox" '
                        'name="restexplorerhonorkey" value="{1}">'
                        ).format(type, key, value, desc, note)
        return snippet


class DeletedResource(ConfluentMessage):
    def __init__(self):
        self.kvpairs = {}


class ConfluentChoiceMessage(ConfluentMessage):

    def html(self):
        snippet = ""
        for key in self.kvpairs.iterkeys():
            val = self.kvpairs[key]
            snippet += key + ':<select name="%s">' % key
            for opt in self.valid_values:
                snippet += opt + ":"
                if opt == val['value']:
                    snippet += '<option value="%s" selected>%s</option>' % (
                        opt, opt)
                else:
                    snippet += '<option value="%s">%s</option>' % (opt, opt)
            snippet += '</select>'
            snippet += '<input type="checkbox" name="restexplorerhonorkey" '
            snippet += 'value="%s">' % (key)
        return snippet


class LinkRelation(ConfluentMessage):
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

    def html(self):
        """Provide an html representation of the link relation.

        This is used by the API explorer aspect of httpapi"""
        return '<a href="{0}" rel="{1}">{0}</a>'.format(self.href, self.rel)
        # return '<a href="%s" rel="%s">%s</a><input type="submit"
        # name="restexprerorop" value="delete:%s"' % (self.href, self.rel,
        # self.href, self.href)


class ChildCollection(LinkRelation):
    def __init__(self, collname, candelete=False):
        self.rel = 'item'
        self.href = collname
        self.candelete = candelete

    def html(self):
        if self.candelete:
            return ('<a href="{0}" rel="{1}">{0}</a> . . . . . . . . . . . . '
                    '<button type="submit" name="restexplorerop" '
                    'value="delete" formaction="{0}">delete'
                    '</button>').format(self.href, self.rel)
        else:
            return '<a href="{0}" rel="{0}">{0}</a>'.format(self.href)


def get_input_message(path, operation, inputdata, nodes=None):
    if path[0] == 'power' and path[1] == 'state' and operation != 'retrieve':
        return InputPowerMessage(path, nodes, inputdata)
    elif path[0] == 'attributes' and operation != 'retrieve':
        return InputAttributes(path, nodes, inputdata)
    elif path == ['boot', 'device'] and operation != 'retrieve':
        return InputBootDevice(path, nodes, inputdata)
    elif inputdata:
        raise exc.InvalidArgumentException()


class InputAttributes(ConfluentMessage):

    def __init__(self, path, nodes, inputdata):
        self.nodeattribs = {}
        nestedmode = False
        if not inputdata:
            raise exc.InvalidArgumentException
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
        return self.nodeattribs[node]


class InputPowerMessage(ConfluentMessage):
    valid_values = set([
        'on',
        'off',
        'reset',
        'boot',
        ])

    def __init__(self, path, nodes, inputdata):
        self.powerbynode = {}
        if not inputdata:
            raise exc.InvalidArgumentException()
        if 'powerstate' not in inputdata:
            #assume we have nested information
            for key in nodes:
                if key not in inputdata:
                    raise exc.InvalidArgumentException()
                datum = inputdata[key]
                if ('powerstate' not in datum or
                        datum['powerstate'] not in self.valid_values):
                    raise exc.InvalidArgumentException()
                self.powerbynode[key] = datum['powerstate']
        else:  # we have a powerstate argument not by node
            datum = inputdata
            if ('powerstate' not in datum or
                    datum['powerstate'] not in self.valid_values):
                raise exc.InvalidArgumentException()
            for node in nodes:
                self.powerbynode[node] = datum['powerstate']

    def powerstate(self, node):
        return self.powerbynode[node]


class BootDevice(ConfluentChoiceMessage):
    valid_values = set([
        'network',
        'hd',
        'setup',
        'default',
        'cd',
        ])

    def __init__(self, node, device):
        if device not in self.valid_values:
            raise Exception("Invalid boot device argument passed in:" + device)
        self.kvpairs = {
            node: {
                'bootdevice': {'value': device},
            }
        }


class InputBootDevice(BootDevice):
    def __init__(self, path, nodes, inputdata):
        self.bootdevbynode = {}
        if not inputdata:
            raise exc.InvalidArgumentException()
        if 'bootdevice' not in inputdata:
            for key in nodes:
                if key not in inputdata:
                    raise exc.InvalidArgumentException()
                datum = inputdata[key]
                if ('powerstate' not in datum or
                        datum['powerstate'] not in self.valid_values):
                    raise exc.InvalidArgumenTException()
                self.bootdevbynode[key] = datum['bootdevice']
        else:
            datum = inputdata
            if ('bootdevice' not in datum or
                    datum['bootdevice'] not in self.valid_values):
                raise exc.InvalidArgumentException()
            for node in nodes:
                self.bootdevbynode[node] = datum['bootdevice']

    def bootdevice(self, node):
        return self.bootdevbynode[node]


class PowerState(ConfluentChoiceMessage):
    valid_values = set([
        'on',
        'off',
        'reset',
        'boot',
        ])

    def __init__(self, node, state):
        self.kvpairs = {
            node: {
                'powerstate': {'value': state},
            }
        }


class Attributes(ConfluentMessage):
    def __init__(self, node=None, kv=None, desc=None):
        self.desc = desc
        nkv = {}
        for key in kv.iterkeys():
            nkv[key] = {'value': kv[key]}
        if node is None:
            self.kvpairs = nkv
        else:
            self.kvpairs = {
                node: nkv
            }


class ListAttributes(ConfluentMessage):
    def __init__(self, node, kv):
        self .kvpairs = {
            node: kv
        }


class CryptedAttributes(Attributes):
    defaulttype = 'password'

    def __init__(self, node=None, kv=None, desc=None):
        # for now, just keep the dictionary keys and discard crypt value
        self.desc = desc
        nkv = {}
        for key in kv.iterkeys():
            nkv[key] = {'note': 'Encrypted'}
        if node is None:
            self.kvpairs = nkv
        else:
            self.kvpairs = {
                node: nkv
            }
