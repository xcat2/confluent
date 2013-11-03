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

    def strip_node(self, node):
        self.kvpairs = self.kvpairs[node]

    def html(self):
        #this is used to facilitate the api explorer feature
        snippet = ""
        for key in self.kvpairs.iterkeys():
            val = self.kvpairs[key]
            label = key
            value = self.defaultvalue
            note = ''
            type = self.defaulttype
            if 'value' in val:
                value = val['value']
            if 'note' in val:
                note = '(' + val['note'] + ')'
            snippet += label + ":" + \
                       '<input type="%s" name="%s" value="%s">%s' % (
                            type, key, value, note)
            snippet += '<input type="checkbox" name="restexplorerhonorkey" '
            snippet += 'value="%s">' % (key)
        return snippet


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
    def json_hal(self):
        return {self.rel: '{ "href": "%s" }' % self.href }

    def html(self):
        return '<a href="%s" rel="%s">%s</a>' % (self.href, self.rel, self.href)



class ChildCollection(LinkRelation):
    def __init__(self, collname):
        self.rel = 'item'
        self.href = collname

def get_input_message(path, operation, inputdata, nodes=None):
    if 'power/state' in path and operation != 'retrieve':
        return InputPowerMessage(path, nodes, inputdata)
    elif path.startswith('attributes/') and operation != 'retrieve':
        return InputAttributes(path, nodes, inputdata)
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
        else: # we have a powerstate argument not by node
            datum = inputdata
            if ('powerstate' not in datum or
                    datum['powerstate'] not in self.valid_values):
                raise exc.InvalidArgumentException()
            for node in nodes:
                self.powerbynode[node] = datum['powerstate']

    def powerstate(self, node):
        return self.powerbynode[node]


class PowerState(ConfluentChoiceMessage):
    valid_values = set([
        'on',
        'off',
        'reset',
        'boot',
        ])

    def __init__(self, node, state, querydict=None):
        self.kvpairs = {
            node: {
                'powerstate': { 'label': 'Power', 'value': state, }
            }
        }

class Attributes(ConfluentMessage):
    def __init__(self, node, kv):
        nkv = {}
        for key in kv.iterkeys():
            nkv[key] = { 'label': key, 'value': kv[key] }
        self.kvpairs = {
            node: nkv
        }

class CryptedAttributes(Attributes):
    defaultvalue = 'dummyvalue'
    defaulttype = 'password'

    def __init__(self, node, kv):
        # for now, just keep the dictionary keys and discard crypt value
        nkv = {}
        for key in kv.iterkeys():
            nkv[key] = { 'label': key, 'note': 'Encrypted' }
        self.kvpairs = {
            node: nkv
        }
