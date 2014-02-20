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

#TODO: clustered mode
# In clustered case, only one instance is the 'master'.  If some 'def set'
# is requested on a slave, it creates a transaction id and an event, firing it
# to master.  It then waits on the event.  When the master reflects the data
# back and that reflection data goes into memory, the wait will be satisfied
# this means that set on a slave will be much longer.
# the assumption is that only the calls to 'def set' need be pushed to/from
# master and all the implicit activity that ensues will pan out since
# the master is ensuring a strict ordering of transactions
# for missed transactions, transaction log will be used to track transactions
# transaction log can have a constrained size if we want, in which case full
# replication will trigger.
# uuid.uuid4() will be used for transaction ids


# on disk format is cpickle.  No data shall be in the configuration db required
# to get started.  For example, argv shall indicate ports rather than cfg store
# TODO(jbjohnso): change to 'anydbm' scheme and actually tie things down

# Note on the cryptography.  Default behavior is mostly just to pave the
# way to meaningful security.  Root all potentially sensitive data in
# one key.  That key is in plain sight, so not meaningfully protected
# However, the key can be protected in the following ways:
#   - Passphrase protected (requiring human interaction every restart)
#   - TPM sealing (which would forgo the interactive assuming risk of
#           physical attack on TPM is not a concern)
# This module provides cryptographic convenience functions, largely to be
# used by config.py to protect/unlock configuration as appropriopriate.
# The default behavior provides no meaningful protection, all encrypted
# values are linked to a master key that is stored in the clear.
# meanigful protection comes when the user elects to protect the key
# by passphrase and optionally TPM


import Crypto.Protocol.KDF as kdf
from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
import array
import ast
import collections
import confluent.config.attributes as allattributes
import confluent.util
import copy
import cPickle
import eventlet
import fcntl
import math
import operator
import os
import re
import string
import threading


_masterkey = None
_masterintegritykey = None



def _derive_keys(passphrase, salt):
    #implement our specific combination of pbkdf2 transforms to get at
    #key.  We bump the iterations up because we can afford to
    tmpkey = kdf.PBKDF2(passphrase, salt, 32, 50000,
                        lambda p, s: HMAC.new(p, s, SHA256).digest())
    finalkey = kdf.PBKDF2(tmpkey, salt, 32, 50000,
                        lambda p, s: HMAC.new(p, s, SHA256).digest())
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
            return decrypt_value(pp[1:], key=privkey, integritykey=integkey)
    else:
        raise Exception("No available decryption key")


def _format_key(key, passphrase=None):
    if passphrase is not None:
        salt = os.urandom(32)
        privkey, integkey = _derive_keys(passphrase, salt)
        cval = crypt_value(key, key=privkey, integritykey=integkey)
        return {"passphraseprotected": cval}
    else:
        return {"unencryptedvalue": key}


def init_masterkey(passphrase=None):
    global _masterkey
    global _masterintegritykey
    cfgn = get_global('master_privacy_key')

    if cfgn:
        _masterkey = _get_protected_key(cfgn, passphrase=passphrase)
    else:
        _masterkey = os.urandom(32)
        configmanager.set_global('master_privacy_key', _format_key(
            _masterkey,
            passphrase=passphrase))
    cfgn = get_global('master_integrity_key')
    if cfgn:
        _masterintegritykey = _get_protected_key(cfgn, passphrase=passphrase)
    else:
        _masterintegritykey = os.urandom(64)
        configmanager.set_global('master_integrity_key', _format_key(
            _masterintegritykey,
            passphrase=passphrase))



def decrypt_value(cryptvalue,
                   key=_masterkey,
                   integritykey=_masterintegritykey):
    iv, cipherdata, hmac = cryptvalue
    if _masterkey is None or _masterintegritykey is None:
        init_masterkey()
    check_hmac = HMAC.new(_masterintegritykey, cipherdata, SHA256).digest()
    if hmac != check_hmac:
        raise Exception("bad HMAC value on crypted value")
    decrypter = AES.new(_masterkey, AES.MODE_CBC, iv)
    value = decrypter.decrypt(cipherdata)
    padsize = ord(value[-1])
    pad = value[-padsize:]
    # Note that I cannot grasp what could be done with a subliminal
    # channel in padding in this case, but check the padding anyway
    for padbyte in pad:
        if ord(padbyte) != padsize:
            raise Exception("bad padding in encrypted value")
    return value[0:-padsize]


def crypt_value(value,
                 key=_masterkey,
                 integritykey=_masterintegritykey):
    # encrypt given value
    # PKCS7 is the padding scheme to employ, if no padded needed, pad with 16
    # check HMAC prior to attempting decrypt
    if key is None or integritykey is None:
        init_masterkey()
        key=_masterkey
        integritykey=_masterintegritykey
    iv = os.urandom(16)
    crypter = AES.new(key, AES.MODE_CBC, iv)
    neededpad = 16 - (len(value) % 16)
    pad = chr(neededpad) * neededpad
    value = value + pad
    cryptval = crypter.encrypt(value)
    hmac = HMAC.new(integritykey, cryptval, SHA256).digest()
    return (iv, cryptval, hmac)



def is_tenant(tenant):
    try:
        return tenant in _cfgstore['tenant']
    except:
        return False

def get_global(globalname):
    """Get a global variable


    :param globalname: The global parameter name to read
    """
    try:
        return _cfgstore['globals'][globalname]
    except:
        return None

def set_global(globalname, value):
    """Set a global variable.

    Globals should be rarely ever used.  Almost everything should be under a
    tenant scope.  Some things like master key and socket numbers/paths can be
    reasonably considered global in nature.

    :param globalname:  The global parameter name to store
    :param value: The value to set the global parameter to.
    """
    if 'globals' not in _cfgstore:
        _cfgstore['globals'] = { globalname: value }
    else:
        _cfgstore['globals'][globalname] = value
    ConfigManager._bg_sync_to_file()


def _generate_new_id():
    # generate a random id outside the usual ranges used for norml users in
    # /etc/passwd.  Leave an equivalent amount of space near the end disused,
    # just in case
    id = confluent.util.securerandomnumber(65537, 4294901759)
    if 'idmap' not in _cfgstore:
        return id
    while id in _cfgstore['idmap']:
        id = confluent.util.securerandomnumber(65537, 4294901759)
    return id

class _ExpressionFormat(string.Formatter):
    # This class is used to extract the literal value from an expression
    # in the db
    # This is made easier by subclassing one of the 'fprintf' mechanisms
    # baked into python
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

    def __init__(self, nodeobj, nodename):
        self._nodeobj = nodeobj
        self._nodename = nodename
        self._numbers = None

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
            if '_expressionkeys' not in self._nodeobj:
                self._nodeobj['_expressionkeys'] = set([key])
            else:
                self._nodeobj['_expressionkeys'].add(key)
            val = _decode_attribute(key, self._nodeobj,
                                    formatter=self)
            return val['value'] if 'value' in val else ""
        elif isinstance(node, ast.Name):
            var = node.id
            if var == 'nodename':
                return self._nodename
            mg = re.match(self.posmatch, var)
            if mg:
                idx = int(mg.group(1))
                if self._numbers == None:
                    self._numbers = re.findall(self.nummatch, self._nodename)
                return int(self._numbers[idx - 1])
            else:
                if var in self._nodeobj:
                    if '_expressionkeys' not in self._nodeobj:
                        self._nodeobj['_expressionkeys'] = set([key])
                    else:
                        self._nodeobj['_expressionkeys'].add(var)
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


def _decode_attribute(attribute, nodeobj, formatter=None, decrypt=False):
    if attribute not in nodeobj:
        return None
    # if we have an expression and a formatter, that overrides 'value'
    # which may be out of date
    # get methods will skip the formatter allowing value to come on through
    # set methods induce recalculation as appropriate to get a cached value
    if 'expression' in nodeobj[attribute] and formatter is not None:
        retdict = copy.deepcopy(nodeobj[attribute])
        retdict['value'] = formatter.format(retdict['expression'])
        return retdict
    elif 'value' in nodeobj[attribute]:
        return nodeobj[attribute]
    elif 'cryptvalue' in nodeobj[attribute] and decrypt:
        retdict = copy.deepcopy(nodeobj[attribute])
        retdict['value'] = decrypt_value(nodeobj[attribute]['cryptvalue'])
        return retdict
    return nodeobj[attribute]


# my thinking at this point is that noderange and configdata  objects
# will be constructed and passed as part of a context object to plugins
# reasoning being that the main program will handle establishing the
# tenant context and then modules need not consider the current tenant
# most of the time as things are automatic

class ConfigManager(object):
    _cfgfilename = "/etc/confluent/cfgdb"
    _cfgwriter = None
    _writepending = False

    def __init__(self, tenant, decrypt=False):
        global _cfgstore
        self.decrypt = decrypt
        if tenant is None:
            self.tenant = None
            if 'main' not in _cfgstore:
                 _cfgstore['main'] = {'id': None}
            self._cfgstore  = _cfgstore['main']
            return
        elif 'tenant' not in _cfgstore:
            _cfgstore['tenant'] = {tenant: {'id': tenant}}
            self._bg_sync_to_file()
        elif tenant not in _cfgstore['tenant']:
            _cfgstore['tenant'][tenant] = {'id': tenant}
            self._bg_sync_to_file()
        self.tenant = tenant
        self._cfgstore = _cfgstore['tenant'][tenant]


    def get_user(self, name):
        """Get user information from DB

        :param name: Name of the user

        Returns a dictionary describing parameters of a user.  These parameters
        may include numeric id (id), certificate thumbprint (certthumb),
        password hash (passhash, which currently is going to be PBKDF2 derived)
        full name (displayname), ...

        """
        try:
            return copy.deepcopy(self._cfgstore['users'][name])
        except:
            return None


    def set_user(self, name, attributemap):
        """Set user attribute(s)

        :param name: The login name of the user
        :param attributemap: A dict of key values to set
        """
        user = self._cfgstore['users'][name]
        for attribute in attributemap:
            user[attribute] = attributemap[attribute]
        self._bg_sync_to_file()

    def create_user(self, name,
                    role="Administrator", id=None, displayname=None):
        """Create a new user

        :param name: The login name of the user
        :param role: The role the user should be considered.  Can be
                     "Administrator" or "Technician", defaults to
                     "Administrator"
        :param id: Custom identifier number if desired.  Defaults to random.
        :param displayname: Optional long format name for UI consumption
        """
        if id is None:
            id = _generate_new_id()
        else:
            if id in _cfgstore['idmap']:
                raise Exception("Duplicate id requested")
        if 'users' not in self._cfgstore:
            self._cfgstore['users'] = { }
        if name in self._cfgstore['users']:
            raise Exception("Duplicate username requested")
        self._cfgstore['users'][name] = {'id': id}
        if displayname is not None:
            self._cfgstore['users'][name]['displayname'] = displayname
        if 'idmap' not in _cfgstore:
            _cfgstore['idmap'] = {}
        _cfgstore['idmap'][id] = {
            'tenant': self.tenant,
            'username': name
            }
        self._bg_sync_to_file()

    def is_node(self, node):
        if 'nodes' not in self._cfgstore:
            return False
        if node not in self._cfgstore['nodes']:
            return False
        return True

    def is_nodegroup(self, nodegroup):
        if 'groups' not in self._cfgstore:
            return False
        if nodegroup not in self._cfgstore['groups']:
            return False
        return True

    def get_groups(self):
        if 'groups' not in self._cfgstore:
            return []
        return self._cfgstore['groups'].iterkeys()

    def get_nodes(self):
        if 'nodes' not in self._cfgstore:
            return []
        return self._cfgstore['nodes'].iterkeys()

    def get_nodegroup_attributes(self, nodegroup, attributes=[]):
        return self._cfgstore['groups'][nodegroup]

    def get_node_attributes(self, nodelist, attributes=[]):
        if 'nodes' not in self._cfgstore:
            return None
        retdict = {}
        if isinstance(nodelist,str):
            nodelist = [nodelist]
        for node in nodelist:
            if node not in self._cfgstore['nodes']:
                continue
            cfgnodeobj = self._cfgstore['nodes'][node]
            nodeobj = {}
            if len(attributes) == 0:
                attributes = cfgnodeobj.iterkeys()
            for attribute in attributes:
                if attribute not in cfgnodeobj:
                    continue
                nodeobj[attribute] = _decode_attribute(attribute, cfgnodeobj,
                                                       decrypt=self.decrypt)
            retdict[node] = nodeobj
        return retdict

    def _node_added_to_group(self, node, group):
        try:
            nodecfg = self._cfgstore['nodes'][node]
            groupcfg = self._cfgstore['groups'][group]
        except KeyError:  # something did not exist, nothing to do
            return
        for attrib in groupcfg.iterkeys():
            self._do_inheritance(nodecfg, attrib, node)

    def _node_removed_from_group(self, node, group):
        try:
            nodecfg = self._cfgstore['nodes'][node]
        except KeyError:  # node did not exist, nothing to do
            return
        for attrib in nodecfg.keys():
            if attrib.startswith("_"):
                continue
            if attrib == 'groups':
                continue
            try:
                if nodecfg[attrib]['inheritedfrom'] == group:
                    del nodecfg[attrib]  # remove invalid inherited data
                    self._do_inheritance(nodecfg, attrib, node)
            except KeyError:  # inheritedfrom not set, move on
                pass

    def _do_inheritance(self, nodecfg, attrib, nodename, srcgroup=None):
        # for now, just do single inheritance
        # TODO: concatenating inheritance if requested
        if attrib in ('nodes', 'groups'):
            #not attributes that should be considered here
            return
        if attrib in nodecfg and 'inheritedfrom' not in nodecfg[attrib]:
            return # already has a non-inherited value set, nothing to do
        # if the attribute is not set, this will search for a candidate
        # if it is set, but inheritedfrom, search for a replacement, just
        # in case
        for group in nodecfg['groups']:
            if attrib in self._cfgstore['groups'][group]:
                if srcgroup is not None and group != srcgroup:
                    # skip needless deepcopy
                    return
                nodecfg[attrib] = \
                    copy.deepcopy(self._cfgstore['groups'][group][attrib])
                nodecfg[attrib]['inheritedfrom'] = group
                self._refresh_nodecfg(nodecfg, attrib, nodename)
                return
            if srcgroup is not None and group == srcgroup:
                # break out
                return

    def _sync_groups_to_node(self, groups, node):
        if 'groups' not in self._cfgstore:
            self._cfgstore['groups'] = {}
        for group in self._cfgstore['groups'].iterkeys():
            if group not in groups:
                if node in self._cfgstore['groups'][group]['nodes']:
                    self._cfgstore['groups'][group]['nodes'].discard(node)
                    self._node_removed_from_group(node, group)
        for group in groups:
            if 'grouplist' not in self._cfgstore:
                self._cfgstore['grouplist'] = [group]
            elif group not in self._cfgstore['grouplist']:
                self._cfgstore['grouplist'].append(group)
            if group not in self._cfgstore['groups']:
                self._cfgstore['groups'][group] = {'nodes': set([node])}
            elif 'nodes' not in self._cfgstore['groups'][group]:
                self._cfgstore['groups'][group]['nodes'] = set([node])
            elif node not in self._cfgstore['groups'][group]['nodes']:
                self._cfgstore['groups'][group]['nodes'].add(node)
            else:
                continue #the group membership already existed, to next group
            # node was not already in given group, perform inheritence fixup
            self._node_added_to_group(node, group)

    def _sync_nodes_to_group(self, nodes, group):
        if 'nodes' not in self._cfgstore:
            self._cfgstore['nodes'] = {}
        for node in self._cfgstore['nodes'].iterkeys():
            if node not in nodes and 'groups' in self._cfgstore['nodes'][node]:
                if group in self._cfgstore['nodes'][node]['groups']:
                    self._cfgstore['nodes'][node]['groups'].remove(group)
                    self._node_removed_from_group(node, group)
        for node in nodes:
            if node not in self._cfgstore['nodes']:
                self._cfgstore['nodes'][node] = {'groups': [group]}
            elif 'groups' not in self._cfgstore['nodes'][node]:
                self._cfgstore['nodes'][node]['groups'] = [group]
            elif group not in self._cfgstore['nodes'][node]['groups']:
                self._cfgstore['nodes'][node]['groups'].insert(0, group)
            else:
                continue # next node, this node already in
            self._node_added_to_group(node, group)

    def set_group_attributes(self, attribmap):
        if 'groups' not in self._cfgstore:
            self._cfgstore['groups'] = {}
        for group in attribmap.iterkeys():
            if group not in self._cfgstore['groups']:
                self._cfgstore['groups'][group] = {'nodes': set([])}
            cfgobj = self._cfgstore['groups'][group]
            for attr in attribmap[group].iterkeys():
                if attr != 'nodes' and (attr not in allattributes.node or
                        ('type' in allattributes.node[attr] and
                        not isinstance(attribmap[node][attr],allattributes.node[attr]['type']))):
                    raise ValueError
                newdict = {}
                if attr == 'nodes':
                    if not isinstance(attribmap[group][attr], list):
                        raise ValueError
                    newdict = set(attribmap[group][attr])
                elif (isinstance(attribmap[group][attr], str)):
                    newdict = { 'value': attribmap[group][attr] }
                else:
                    newdict = attribmap[group][attr]
                if 'value' in newdict and attr.startswith("secret."):
                    newdict['cryptvalue'] = crypt_value(newdict['value'])
                    del newdict['value']
                cfgobj[attr] = newdict
                if attr == 'nodes':
                    self._sync_nodes_to_group(group=group,
                        nodes=attribmap[group]['nodes'])
                else:  # update inheritence
                    for node in cfgobj['nodes']:
                        nodecfg = self._cfgstore['nodes'][node]
                        self._do_inheritance(nodecfg, attr, node, srcgroup=group)
        self._bg_sync_to_file()

    def _refresh_nodecfg(self, cfgobj, attrname, node):
        exprmgr = None
        if 'expression' in cfgobj[attrname]:  # evaluate now
            if exprmgr is None:
                exprmgr = _ExpressionFormat(cfgobj, node)
            cfgobj[attrname] = _decode_attribute(attrname, cfgobj,
                                                 formatter=exprmgr)
        if ('_expressionkeys' in cfgobj and
                attrname in cfgobj['_expressionkeys']):
            if exprmgr is None:
                exprmgr = _ExpressionFormat(cfgobj, node)
            self._recalculate_expressions(cfgobj, formatter=exprmgr)

    def del_nodes(self, nodes):
        if 'nodes' not in self._cfgstore:
            return
        for node in nodes:
            if node in self._cfgstore['nodes']:
                self._sync_groups_to_node(node=node, groups=[])
                del self._cfgstore['nodes'][node]
        self._bg_sync_to_file()

    def del_groups(self, groups):
        if 'groups' not in self._cfgstore:
            return
        for group in groups:
            if group in self._cfgstore['groups']:
                self._sync_nodes_to_group(group=group, nodes=[])
                del self._cfgstore['groups'][group]
        self._bg_sync_to_file()

    def clear_node_attributes(self, nodes, attributes):
        for node in nodes:
            try:
                nodek = self._cfgstore['nodes'][node]
            except KeyError:
                continue
            for attrib in attributes:
                if attrib in nodek and 'inheritedfrom' not in nodek[attrib]:
                    # if the attribute is set and not inherited,
                    # delete it and check for inheritence to backfil data
                    del nodek[attrib]
                    self._do_inheritance(nodek, attrib, node)
        self._bg_sync_to_file()

    def set_node_attributes(self, attribmap):
        if 'nodes' not in self._cfgstore:
            self._cfgstore['nodes'] = {}
        # TODO(jbjohnso): multi mgr support, here if we have peers,
        # pickle the arguments and fire them off in eventlet
        # flows to peers, all should have the same result
        for node in attribmap.iterkeys():
            if node not in self._cfgstore['nodes']:
                self._cfgstore['nodes'][node] = {}
            cfgobj = self._cfgstore['nodes'][node]
            recalcexpressions = False
            for attrname in attribmap[node].iterkeys():
                if (attrname not in allattributes.node or
                        ('type' in allattributes.node[attrname] and
                        not isinstance(attribmap[node][attrname],allattributes.node[attrname]['type']))):
                    raise ValueError
                newdict = {}
                if (isinstance(attribmap[node][attrname], str)):
                    newdict = {'value': attribmap[node][attrname] }
                else:
                    newdict = attribmap[node][attrname]
                if 'value' in newdict and attrname.startswith("secret."):
                    newdict['cryptvalue' ] = crypt_value(newdict['value'])
                    del newdict['value']
                cfgobj[attrname] = newdict
                if attrname == 'groups':
                    self._sync_groups_to_node(node=node,
                    groups=attribmap[node]['groups'])
                if ('_expressionkeys' in cfgobj and
                        attrname in cfgobj['_expressionkeys']):
                    recalcexpressions = True
                if 'expression' in cfgobj[attrname]:  # evaluate now
                    if exprmgr is None:
                        exprmgr = _ExpressionFormat(cfgobj, node)
                    cfgobj[attrname] = _decode_attribute(attrname, cfgobj,
                                                         formatter=exprmgr)
            if recalcexpressions:
                if exprmgr is None:
                    exprmgr = _ExpressionFormat(cfgobj, node)
                self._recalculate_expressions(cfgobj, formatter=exprmgr)
        self._bg_sync_to_file()
        #TODO: wait for synchronization to suceed/fail??)

    @classmethod
    def _read_from_file(cls):
        global _cfgstore
        nhandle = open(cls._cfgfilename, 'rb')
        fcntl.lockf(nhandle, fcntl.LOCK_SH)
        _cfgstore = cPickle.load(nhandle)
        fcntl.lockf(nhandle, fcntl.LOCK_UN)

    @classmethod
    def _bg_sync_to_file(cls):
        if cls._writepending:
            # already have a write scheduled
            return
        elif cls._cfgwriter is not None and cls._cfgwriter.isAlive():
            #write in progress, request write when done
            cls._writepending = True
        else:
            cls._cfgwriter = threading.Thread(target=cls._sync_to_file)
            cls._cfgwriter.start()

    @classmethod
    def _sync_to_file(cls):
        # TODO: this is a pretty nasty performance penalty to pay
        # as much as it is mitigated and deferred, still need to do better
        # possibilities include:
        # doing dbm for the major trees, marking the objects that need update
        # and only doing changes for those
        # the in memory facet seems serviceable though
        nfn = cls._cfgfilename + '.new'
        nhandle = open(nfn, 'wb')
        fcntl.lockf(nhandle, fcntl.LOCK_EX)
        cPickle.dump(_cfgstore, nhandle, protocol=2)
        fcntl.lockf(nhandle, fcntl.LOCK_UN)
        nhandle.close()
        try:
            os.rename(cls._cfgfilename, cls._cfgfilename + '.old')
        except OSError:
            pass
        os.rename(nfn, cls._cfgfilename)
        if cls._writepending:
            cls._writepending = False
            return cls._sync_to_file()

    def _recalculate_expressions(self, cfgobj, formatter):
        for key in cfgobj.iterkeys():
            if not isinstance(cfgobj[key],dict):
                continue
            if 'expression' in cfgobj[key]:
                cfgobj[key] = _decode_attribute(key, cfgobj,
                                                formatter=formatter)
            elif ('cryptvalue' not in cfgobj[key] and
                    'value' not in cfgobj[key]):
                # recurse for nested structures, with some hint tha
                # it might indeed be a nested structure
                _recalculate_expressions(cfgobj[key], formatter)


try:
    ConfigManager._read_from_file()
except IOError:
    _cfgstore = {}

