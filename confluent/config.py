# Copyright 2013 IBM
# All rights reserved


# Ultimately, the design is to handle all the complicated stuff at set
# rather than get tiime.  When something is set on a group, then all
# members of that group are examined  and 'inheritedfrom' attributes
# are pushed.  as expression definned values are iinserted, their
#  dependdentt attributes are added to a private dict to aid in auto
# calculation.  When a name is changed, all attributes are re-evaluated
# on get, should be simple read value *except* for encrypted values,
# which are only decrypted when explicitly requested
# encrypted fields do not support expressions, either as a source or
# destination

# For multi-node operation, each instance opens and retains a TLS connection
# to each other instance.  'set' operations push to queue for writeback and
# returns.  The writeback thread writes to local disk and to other instances.
# A function is provided to wait for pending output to disk and peers to complete
# to assure that aa neww requesst to  peer does not beat configuration data to
# the target

# on disk format is cpickle.  No data shall be in the configuration db required
# to get started.  For example, argv shall indicate ports rather than cfg store

# Note on the cryptography.  Default behavior is mostly just to pave the
# way to meaningful security.  Root all potentially sensitive data in
# one key.  That key is in plain sight, so not meaningfully protected
# However, the key can be protected in the following ways:
#   - Passphrase protected (requiring human interaction every restart)
#   - TPM sealing (which would forgo the interactive assuming risk of
#           physical attack on TPM is not a concern)


import array
import ast
import collections
import copy
import math
import operator
import os
import re
import string



class _ExpressionFormat(string.Formatter):
    posmatch = re.compile('^n([0-9]*)$')
    nummatch = re.compile('[0-9]+')
    _supported_ops = {
        ast.Mult: operator.mul,
        ast.Div: operator.floordiv,
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.LShift: operator.lshift,
        ast.RShift: operator.rshift,
        ast.BitAnd: operator.and_,
        ast.BitXor: operator.xor,
        ast.BitOr: operator.or_,
    }

    def __init__(self, nodeobj):
        self._nodeobj = nodeobj
        self._numbers = re.findall(self.nummatch, nodeobj['name']['value'])

    def get_field(self, field_name, args, kwargs):
        parsed = ast.parse(field_name)
        return (self._handle_ast_node(parsed.body[0].value), field_name)

    def _handle_ast_node(self, node):
        if isinstance(node, ast.Num):
            return node.n
        elif isinstance(node, ast.Attribute):
            #ok, we have something with a dot
            left = node.value.id
            right = node.attr
            key = left + '.' + right
            val = _decode_attribute(key, self._nodeobj,
                                    formatter=self)
            return val['value'] if 'value' in val else ""
        elif isinstance(node, ast.Name):
            var = node.id
            if var == 'nodename':
                return self._nodeobj['name']['value']
            mg = re.match(self.posmatch, var)
            if mg:
                idx = int(mg.group(1))
                return int(self._numbers[idx - 1])
            else:
                if var in self._nodeobj:
                    val = _decode_attribute(var, self._nodeobj,
                                            formatter=self)
                    return val['value'] if 'value' in val else ""
        elif isinstance(node, ast.BinOp):
            optype = type(node.op)
            if optype not in self._supported_ops:
                raise Exception("Unsupported operation")
            op = self._supported_ops[optype]
            return op(self._handle_ast_node(node.left),
               self._handle_ast_node(node.right))


def _decode_attribute(attribute, nodeobj, formatter, decrypt=False):
    if attribute not in nodeobj:
        return None
    if 'value' in nodeobj[attribute]:
        return nodeobj[attribute]
    elif 'expression' in  nodeobj[attribute]:
        retdict = copy.deepcopy(nodeobj[attribute])
        retdict['value'] = formatter.format(retdict['expression'])
        return retdict
    elif 'cryptvalue' in nodeobj[attribute] and decrypt:
        retdict = copy.deepcopy(nodeobj[attribute])
        retdict['value'] = crypto.decrypt_value(
                                nodeobj[attribute]['cryptvalue'])
    return nodeobj[attribute]


def _expand_expression(attribute, nodeobj, decrypt=False):
    # here is where we may avail ourselves of string.Formatter or
    # string.Template
    # we would then take the string that is identifier and do
    # a little ast magic
    # {(n1+1)/12+1} would take first number from nodename
    # {enclosure.id * 8} would take enclosure.id value
    # ast scheme would envolve the operator module and ast
    # modules, with a mapping from ast operator classes to
    # valid operator functions
    # ast.parse gives a body array, and value is where we kick off
    # ast.Num has an 'n' member to give the number
    # ast.Attribute o
#>>> import ast
#>>> b=ast.parse("enclosure.id+n0+1/2")
#>>> b.body[0].value
#<_ast.BinOp object at 0x7ff449ff0090>
#>>> b.body[0].value.op
#<_ast.Add object at 0x7ff4500faf90>
#>>> b.body[0].value.left
#<_ast.BinOp object at 0x7ff449ff00d0>
#>>> b.body[0].value.left.op
#<_ast.Add object at 0x7ff4500faf90>
#>>> b.body[0].value.left.left
#<_ast.Attribute object at 0x7ff449ff0110>
#>>> b.body[0].value.left.left.value.id
#'enclosure'
#>>> b.body[0].value.left.right
#<_ast.Name object at 0x7ff449ff0190>
#>>> b.body[0].value.left.right.id
#'n0'
#>>> b.body[0].value.left.left.id
#Traceback (most recent call last):
#  File "<stdin>", line 1, in <module>
#AttributeError: 'Attribute' object has no attribute 'id'
#>>> b.body[0].value.left.left.attr
#'id'
#import ast
#import operator as op
# supported operators
#operators = {ast.Add: op.add, ast.Sub: op.sub, ast.Mult: op.mul,
#            ast.Div: op.truediv, ast.Pow: op.pow, ast.BitXor: op.xor}
#ef eval_expr(expr):
#   """
#   >>> eval_expr('2^6')
#   4
#   >>> eval_expr('2**6')
#   64
#   >>> eval_expr('1 + 2*3**(4^5) / (6 + -7)')
#   -5.0
#   """
#   return eval_(ast.parse(expr).body[0].value) # Module(body=[Expr(value=...)])
#ef eval_(node):
#   if isinstance(node, ast.Num): # <number>
#       return node.n
#   elif isinstance(node, ast.operator): # <operator>
#       return operators[type(node)]
#   elif isinstance(node, ast.BinOp): # <left> <operator> <right>
#       return eval_(node.op)(eval_(node.left), eval_(node.right))
#   else:
#       raise TypeError(node)
    pass

_cfgstore = {}

# my thinking at this point is that noderange and configdata  objects
# will be constructed and passed as part of a context object to plugins
# reasoning being that the main program will handle establishing the
# tenant context and then modules need not consider the current tenant
# most of the time as things are automatic

class ConfigData(object):
    def __init__(self, tenant=0, decrypt=False):
        self._tenant = tenant
        self.decrypt = decrypt

    def get_node_attributes(self, nodelist, attributes=[]):
        if 'node' not in _cfgstore:
            return None
        retdict = {}
        if isinstance(nodelist,str):
            nodelist = [nodelist]
        for node in nodelist:
            if (self._tenant,node) not in _cfgstore['node']:
                continue
            cfgnodeobj = _cfgstore['node'][(self._tenant,node)]
            exprmgr = _ExpressionFormat(cfgnodeobj)
            nodeobj = {}
            if len(attributes) == 0:
                attributes = cfgnodeobj.keys()
            for attribute in attributes:
                if attribute not in cfgnodeobj:
                    continue
                nodeobj[attribute] = _decode_attribute(attribute, cfgnodeobj,
                                                       formatter=exprmgr,
                                                       decrypt=self.decrypt)
            retdict[node] = nodeobj
        return retdict

    def set_node_attributes(self, attribmap):
        if 'node' not in _cfgstore:
            _cfgstore['node'] = {}
        for node in attribmap.keys():
            key = (self._tenant, node)
            if key not in _cfgstore['node']:
                _cfgstore['node'][key] = {'name': {'value': node}}
            for attrname in attribmap[node].keys():
                newdict = {}
                if isinstance(attribmap[node][attrname], dict):
                    newdict = attribmap[node][attrname]
                else:
                    newdict = {'value': attribmap[node][attrname] }
                if 'value' in newdict and attrname.startswith("credential"):
                    newdict['cryptvalue' ] = \
                        crypto.crypt_value(newdict['value'])
                    del newdict['value']
                _cfgstore['node'][key][attrname] = newdict

