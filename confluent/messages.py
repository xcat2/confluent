#Copyright 2013 IBM All rights reserved

# This module implements client/server messages emitted from plugins.
# Things are defined here to 'encourage' developers to coordinate information
# format.  This is also how different data formats are supported
import confluent.exceptions as exc
import json

class ConfluentMessage(object):

    def __init__(self):
        raise NotImplementedError("Must be subclassed!")

    def json(self):
        # This will create the canonical json representation of this message
        return json.dumps(self.kvpairs, separators=(',', ':'))

    def strip_node(self, node):
        self.kvpairs = self.kvpairs[node]

    def html(self):
        #this is used to facilitate the api explorer feature
        snippet = ""
        for key in self.kvpairs.iterkeys():
            val = self.kvpairs[key]
            label = key
            value = ''
            note = ''
            if 'value' in val:
                value = val['value']
            if 'note' in val:
                note = '(' + val['note'] + ')'
            snippet += label + ":" + \
                       '<input type="text" name="%s" value="%s">%s' % (
                            key, value, note)
            snippet += '<input type="checkbox" name="restexplorerhonorkey" '
            snippet += 'value="%s">' % (key)
        return snippet


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


class InputPowerMessage(ConfluentMessage):
    valid_powerstates = set([
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
                        datum['powerstate'] not in self.valid_powerstates):
                    raise exc.InvalidArgumentException()
                self.powerbynode[key] = datum['powerstate']
        else: # we have a powerstate argument not by node
            datum = inputdata
            if ('powerstate' not in datum or
                    datum['powerstate'] not in self.valid_powerstates):
                raise exc.InvalidArgumentException()
            for node in nodes:
                self.powerbynode[node] = datum['powerstate']

    def powerstate(self, node):
        return self.powerbynode[node]


class PowerState(ConfluentMessage):

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
    def __init__(self, node, kv):
        # for now, just keep the dictionary keys and discard crypt value
        nkv = {}
        for key in kv.iterkeys():
            nkv[key] = { 'label': key, 'note': 'Encrypted' }
        self.kvpairs = {
            node: nkv
        }
