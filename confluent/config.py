# Copyright 2013 IBM
# All rights reserved


# Note on the cryptography.  Default behavior is mostly just to pave the
# way to meaningful security.  Root all potentially sensitive data in 
# one key.  That key is in plain sight, so not meaningfully protected
# However, the key can be protected in the following ways:
#   - Passphrase protected (requiring human interaction every restart)
#   - TPM sealing (which would forgo the interactive assuming risk of
#           physical attack on TPM is not a concern)

# This time around, expression based values will be parsed when set, and the
# parsing results will be stored rather than parsing on every evaluation
# Additionally, the option will be made available to use other attributes
# as well as the $1, $2, etc extracted from nodename.  Left hand side can
# be requested to customize $1 and $2, but it is not required

#Actually, may override one of the python string formatters:
#   2.6 String.Formatter, e.g. "hello {world}"
#   2.4 string.Template, e.g. "hello $world"

# In JSON mode, will just read and write entire thing, with a comment
# to dissuade people from hand editing.

# In JSON mode, a file for different categories (site, nodes, etc)
# in redis, each category is a different database number

import array
import collections
import math
import os


_masterintegritykey = None
_cfgstore = {}

def _expand_expression(attribute, nodeobj):
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


class NodeAttribs(object):
    def __init__(self, nodes=[], attributes=[], tenant=0):
        self._nodelist = collecitons.dequeue(nodes)
        self._tenant = tenant
        self._attributes=attributes

    def __iter__(self):
        return self

    def next():
        node = self._nodelist.popleft()
        onodeobj = _cfgstore['node'][(self._tenant,node)]
        nodeobj = 
        attriblist = []
        #if there is a filter, delete irrelevant keys
        if self._attributes.length > 0:
            for attribute in nodeobj.keys():
                if attribute not in self._attributes:
                    del nodeobj[attribute]
        #now that attributes are filtered, seek out and evaluate expressions
        for attribute in nodeobj.keys():
            if ('value' not in nodeobj[attribute] and
                    'cryptvalue' in nodeobj[attribute]):
                nodeobj[attribute]['value'] = _decrypt_value(
                                            nodeobj[attribute]['cryptvalue'])
            if ('value' not in nodeobj[attribute] and
                    'expression' in nodeobj[attribute]):
                nodeobj[attribute]['value'] = _expand_expression(
                                                attribute=attribute,
                                                nodeobj=nodeobj)


