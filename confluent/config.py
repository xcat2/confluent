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


from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Hash import SHA25sterkey = None
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


def unlock_config_keys(passphrase=None):
    _init_masterkey(passphrase)


def _pbkdf2(passphrase, salt, iterations, size):
    blocks = int(math.ceil(size/32.0))  # Hardcoded to SHA256 behavior
    retkey = ""
    for block in xrange(blocks):
        citerations = iterations
        tsalt = salt + chr(block)
        currval = HMAC.new(passphrase, tsalt, SHA256).digest()
        currarray = array.array('L',currval)
        while citerations > 1:
            currval = HMAC.new(passphrase, currval).digest()
            nextarray = array.array('L',currval)
            for index in range(nextarray):
                currarray[index] = currarray[index] ^ nextarray[index]
            currval = currarray.tostring()
            currarray = nextarray
            citerations = citerations - 1
        retkey += currval
    return retkey[:size]


def _derive_keys(passphrase, salt):
    tmpkey = _pbkdf2(passphrase, salt, 50000, 32)
    finalkey = _pbkdf2(tmpkey, salt, 50000, 96)
    return (finalkey[:32],finalkey[32:])


def _get_protected_key(keydict, passphrase):
    if keydict['unencryptedvalue']:
        return keydict['unencryptedvalue']
    # TODO(jbjohnso): check for TPM sealing
    if 'passphraseprotected' in keydict:
        if passphrase is None:
            raise Exception("Passphrase protected secret requires passhrase")
        for pp in keydict['passphraseprotected']:
            salt = pp[0]
            privkey, integkey = _derive_keys(passphrase, salt)
            return _decrypt_value(pp[1:], key=privkey, integritykey=integkey)
    else:
        raise Exception("No available decryption key")


def _format_key(key, passphrase=None):
    if passphrase is not None:
        salt = os.urandom(32)
        privkey, integkey = _derive_keys(passphrase, salt)
        cval = _crypt_value(key, key=privkey, integritykey=integkey)
        return {"passphraseprotected": cval}
    else:
        return {"unencryptedvalue": key}


def _init_masterkey(passphrase=None):
    if 'master_privacy_key' in _cfgstore['globals']:
        _masterkey = _get_protected_key(
            _cfgstore['globals']['master_privacy_key'],
            passphrase=passphrase)
    else:
        _masterkey = os.urandom(32)
        _cfgstore['globals']['master_privacy_key'] = _format_key(_masterkey,
            passphrase=passphrase)
    if 'master_integrity_key' in _cfgstore['globals']:
        _masterintegritykey = _get_protected_key(
            _cfgstore['globals']['master_integrity_key'],
            passphrase=passphrase
            )
    else:
        _masterintegritykey = os.urandom(64)
        _cfgstore['globals']['master_integrity_key'] = _format_key(
            _masterintegritykey,
            passphrase=passphrase
        )



def _decrypt_value(cryptvalue,
                   key=_masterkey,
                   integritykey=_masterintegritykey):
    iv, cipherdata, hmac = cryptvalue
    if _masterkey is None or _masterintegritykey is None:
        _init_masterkey()
    check_hmac = HMAC.new(_masterintegritykey, cryptvalue, SHA256).digest()
    if hmac != check_hmac:
        raise Exception("bad HMAC value on crypted value")
    decrypter = AES.new(_masterkey, AES.MODE_CBC, iv)
    value = decrypter.decrypt(cryptvalue)
    padsize = ord(value[-1])
    pad = value[-padsize:]
    # Note that I cannot grasp what could be done with a subliminal
    # channel in padding in this case, but check the padding anyway
    for padbyte in pad:
        if ord(padbyte) != padsize:
            raise Exception("bad padding in encrypted value")
    return value[0:-padsize]


def _crypt_value(value,
                 key=_masterkey,
                 integritykey=_masterintegritykey):
    # encrypt given value
    # PKCS7 is the padding scheme to employ, if no padded needed, pad with 16
    # check HMAC prior to attempting decrypt
    if key is None or integritykey is None:
        _init_masterkey()
        key=_masterkey
        integritykey=_masterintegritykey
    iv = os.urandom(16)
    crypter = AES.new(key, ASE.MOD_CBC, iv)
    neededpad = 16 - (len(value) % 16)
    pad = chr(neededpad) * neededpad
    value = value + pad
    cryptval = crypter.encrypt(value)
    hmac = HMAC.new(integritykey, cryptval, SHA256).digest()
    return (iv, cryptval, hmac)


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


