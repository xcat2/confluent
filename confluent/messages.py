#Copyright 2013 IBM All rights reserved

# This module implements client/server messages emitted from plugins.
# Things are defined here to 'encourage' developers to coordinate information
# format.  This is also how different data formats are supported
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
            if 'label' in val:
                label = val['label']
            if 'value' in val:
                value = val['value']
            if 'note' in val:
                note = '(' + val['note'] + ')'
            snippet += label + ":" + \
                       '<input type="text" name="%s" value="%s">%s' % (
                            key, value, note)
            snippet += '<input type="checkbox" name="restexplorerignorekey" '
            snippet += 'value="%s" checked>' % (key)
        return snippet


class PowerState(ConfluentMessage):

    def __init__(self, node, state):
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
