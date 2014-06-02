# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 IBM Corporation
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


import Crypto.Protocol.KDF as KDF
from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
import anydbm as dbm
import ast
import confluent.config.attributes as allattributes
import confluent.util
import copy
import cPickle
import errno
import operator
import os
import random
import re
import string
import sys
import threading


_masterkey = None
_masterintegritykey = None
_dirtylock = threading.RLock()


def _mkpath(pathname):
    try:
        os.makedirs(pathname)
    except OSError as e:
        if e.errno == errno.EEXIST and os.path.isdir(pathname):
            pass
        else:
            raise


def _derive_keys(passphrase, salt):
    #implement our specific combination of pbkdf2 transforms to get at
    #key.  We bump the iterations up because we can afford to
    #TODO: WORKERPOOL PBKDF2 is expensive
    tmpkey = KDF.PBKDF2(passphrase, salt, 32, 50000,
                        lambda p, s: HMAC.new(p, s, SHA256).digest())
    finalkey = KDF.PBKDF2(tmpkey, salt, 32, 50000,
                          lambda p, s: HMAC.new(p, s, SHA256).digest())
    return finalkey[:32], finalkey[32:]


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
        set_global('master_privacy_key', _format_key(
            _masterkey,
            passphrase=passphrase))
    cfgn = get_global('master_integrity_key')
    if cfgn:
        _masterintegritykey = _get_protected_key(cfgn, passphrase=passphrase)
    else:
        _masterintegritykey = os.urandom(64)
        set_global('master_integrity_key', _format_key(
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
        key = _masterkey
        integritykey = _masterintegritykey
    iv = os.urandom(16)
    crypter = AES.new(key, AES.MODE_CBC, iv)
    neededpad = 16 - (len(value) % 16)
    pad = chr(neededpad) * neededpad
    value += pad
    cryptval = crypter.encrypt(value)
    hmac = HMAC.new(integritykey, cryptval, SHA256).digest()
    return iv, cryptval, hmac


def _load_dict_from_dbm(dpath, tdb):
    try:
        dbe = dbm.open(tdb, 'r')
        currdict = _cfgstore
        for elem in dpath:
            if elem not in currdict:
                currdict[elem] = {}
            currdict = currdict[elem]
        for tk in dbe.iterkeys():
            currdict[tk] = cPickle.loads(dbe[tk])
    except dbm.error:
        return


def is_tenant(tenant):
    try:
        return tenant in _cfgstore['tenant']
    except KeyError:
        return False


def get_global(globalname):
    """Get a global variable


    :param globalname: The global parameter name to read
    """
    try:
        return _cfgstore['globals'][globalname]
    except KeyError:
        return None


def set_global(globalname, value):
    """Set a global variable.

    Globals should be rarely ever used.  Almost everything should be under a
    tenant scope.  Some things like master key and socket numbers/paths can be
    reasonably considered global in nature.

    :param globalname:  The global parameter name to store
    :param value: The value to set the global parameter to.
    """
    with _dirtylock:
        if 'dirtyglobals' not in _cfgstore:
            _cfgstore['dirtyglobals'] = set()
        _cfgstore['dirtyglobals'].add(globalname)
    if 'globals' not in _cfgstore:
        _cfgstore['globals'] = {globalname: value}
    else:
        _cfgstore['globals'][globalname] = value
    ConfigManager._bg_sync_to_file()


def _mark_dirtykey(category, key, tenant=None):
    if type(key) in (str, unicode):
        key = key.encode('utf-8')
    with _dirtylock:
        if 'dirtykeys' not in _cfgstore:
            _cfgstore['dirtykeys'] = {}
        if tenant not in _cfgstore['dirtykeys']:
            _cfgstore['dirtykeys'][tenant] = {}
        if category not in _cfgstore['dirtykeys'][tenant]:
            _cfgstore['dirtykeys'][tenant][category] = set()
        _cfgstore['dirtykeys'][tenant][category].add(key)


def _generate_new_id():
    # generate a random id outside the usual ranges used for norml users in
    # /etc/passwd.  Leave an equivalent amount of space near the end disused,
    # just in case
    uid = str(confluent.util.securerandomnumber(65537, 4294901759))
    if 'idmap' not in _cfgstore['main']:
        return uid
    while uid in _cfgstore['main']['idmap']:
        uid = str(confluent.util.securerandomnumber(65537, 4294901759))
    return uid


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
        ast.Mod: operator.mod,
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
        return self._handle_ast_node(parsed.body[0].value), field_name

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
                if self._numbers is None:
                    self._numbers = re.findall(self.nummatch, self._nodename)
                return int(self._numbers[idx - 1])
            else:
                if var in self._nodeobj:
                    if '_expressionkeys' not in self._nodeobj:
                        self._nodeobj['_expressionkeys'] = set([var])
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
        if 'value' in retdict:
            del retdict['value']
        try:
            retdict['value'] = formatter.format(retdict['expression'])
        except Exception as e:
            retdict['broken'] = str(e)
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

def _addchange(changeset, node, attrname):
    if node not in changeset:
        changeset[node] = {attrname: 1}
    else:
        changeset[node][attrname] = 1


def hook_new_configmanagers(callback):
    """Register callback for new tenants

    From the point when this function is called until the end,
    callback may be invoked to indicate a new tenant and
    callback is notified to perform whatever tasks appropriate for
    a new tenant

    :param callback: Function to call for each possible config manager
    :returns: identifier that can be used to cancel this registration
    """
    #TODO(jbjohnso): actually live up to the promise of ongoing callbacks
    callback(ConfigManager(None))
    try:
        for tenant in _cfgstore['tenant'].iterkeys():
            callback(ConfigManager(tenant))
    except KeyError:
        pass


class ConfigManager(object):
    _cfgdir = "/etc/confluent/cfg/"
    _cfgwriter = None
    _writepending = False
    _attribwatchers = {}
    _nodecollwatchers = {}
    _notifierids = {}

    def __init__(self, tenant, decrypt=False):
        global _cfgstore
        self.decrypt = decrypt
        if tenant is None:
            self.tenant = None
            if 'main' not in _cfgstore:
                _cfgstore['main'] = {}
                self._bg_sync_to_file()
            self._cfgstore = _cfgstore['main']
            if 'groups' not in self._cfgstore:
                self._cfgstore['groups'] = {'everything': {'nodes': set()}}
                self._bg_sync_to_file()
            if 'nodes' not in self._cfgstore:
                self._cfgstore['nodes'] = {}
                self._bg_sync_to_file()
            return
        elif 'tenant' not in _cfgstore:
            _cfgstore['tenant'] = {tenant: {}}
            self._bg_sync_to_file()
        elif tenant not in _cfgstore['tenant']:
            _cfgstore['tenant'][tenant] = {}
            self._bg_sync_to_file()
        self.tenant = tenant
        self._cfgstore = _cfgstore['tenant'][tenant]
        if 'groups' not in self._cfgstore:
            self._cfgstore['groups'] = {'everything': {}}
        if 'nodes' not in self._cfgstore:
            self._cfgstore['nodes'] = {}
        self._bg_sync_to_file()

    def watch_attributes(self, nodes, attributes, callback):
        """
        Watch a list of attributes for changes on a list of nodes

        :param nodes: An iterable of node names to be watching
        :param attributes: An iterable of attribute names to be notified about
        :param callback: A callback to process a notification

        Returns an identifier that can be used to unsubscribe from these
        notifications using remove_watcher
        """
        notifierid = random.randint(0, sys.maxint)
        while notifierid in self._notifierids:
            notifierid = random.randint(0, sys.maxint)
        self._notifierids[notifierid] = {'attriblist': []}
        if self.tenant not in self._attribwatchers:
            self._attribwatchers[self.tenant] = {}
        attribwatchers = self._attribwatchers[self.tenant]
        for node in nodes:
            if node not in attribwatchers:
                attribwatchers[node] = {}
            for attribute in attributes:
                self._notifierids[notifierid]['attriblist'].append(
                    (node, attribute))
                if attribute not in attribwatchers[node]:
                    attribwatchers[node][attribute] = {
                        notifierid: callback
                    }
                else:
                    attribwatchers[node][attribute][notifierid] = callback
        return notifierid

    def watch_nodecollection(self, callback):
        """
        Watch the nodecollection for addition or removal of nodes.

        A watcher is notified prior after node has been added and before node
        is actually removed.

        :param callback: Function to call when a node is added or removed

        Returns an identifier that can be used to unsubscribe from these
        notifications using remove_watcher
        """
        # first provide an identifier for the calling code to
        # use in case of cancellation.
        # I anticipate no more than a handful of watchers of this sort, so
        # this loop should not have to iterate too many times
        notifierid = random.randint(0, sys.maxint)
        while notifierid in self._notifierids:
            notifierid = random.randint(0, sys.maxint)
        # going to track that this is a nodecollection type watcher,
        # but there is no additional data associated.
        self._notifierids[notifierid] = set(['nodecollection'])
        if self.tenant not in self._nodecollwatchers:
            self._nodecollwatchers[self.tenant] = {}
        self._nodecollwatchers[self.tenant][notifierid] = callback
        return notifierid

    def remove_watcher(self, watcher):
        # identifier of int would be a collection watcher
        if watcher not in self._notifierids:
            raise Exception("Invalid")
            # return
        if 'attriblist' in self._notifierids[watcher]:
            attribwatchers = self._attribwatchers[self.tenant]
            for nodeattrib in self._notifierids[watcher]['attriblist']:
                node, attrib = nodeattrib
                del attribwatchers[node][attrib][watcher]
        elif 'nodecollection' in self._notifierids[watcher]:
            del self._nodecollwatchers[self.tenant][watcher]
        else:
            raise Exception("Completely not a valid place to be")
        del self._notifierids[watcher]

    def list_users(self):
        try:
            return self._cfgstore['users'].iterkeys()
        except KeyError:
            return []

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
        except KeyError:
            return None

    def set_user(self, name, attributemap):
        """Set user attribute(s)

        :param name: The login name of the user
        :param attributemap: A dict of key values to set
        """
        user = self._cfgstore['users'][name]
        for attribute in attributemap:
            if attribute == 'passphrase':
                salt = os.urandom(8)
                #TODO: WORKERPOOL, offload password set to a worker
                crypted = KDF.PBKDF2(
                    attributemap[attribute], salt, 32, 10000,
                    lambda p, s: HMAC.new(p, s, SHA256).digest()
                )
                user['cryptpass'] = (salt, crypted)
            else:
                user[attribute] = attributemap[attribute]
        _mark_dirtykey('users', name, self.tenant)
        self._bg_sync_to_file()

    def del_user(self, name):
        if name in self._cfgstore['users']:
            del self._cfgstore['users'][name]
            _mark_dirtykey('users', name, self.tenant)
        self._bg_sync_to_file()

    def create_user(self, name,
                    role="Administrator", uid=None, displayname=None,
                    attributemap=None):
        """Create a new user

        :param name: The login name of the user
        :param role: The role the user should be considered.  Can be
                     "Administrator" or "Technician", defaults to
                     "Administrator"
        :param uid: Custom identifier number if desired.  Defaults to random.
        :param displayname: Optional long format name for UI consumption
        """
        if uid is None:
            uid = _generate_new_id()
        else:
            if uid in _cfgstore['main']['idmap']:
                raise Exception("Duplicate id requested")
        if 'users' not in self._cfgstore:
            self._cfgstore['users'] = {}
        name = name.encode('utf-8')
        if name in self._cfgstore['users']:
            raise Exception("Duplicate username requested")
        self._cfgstore['users'][name] = {'id': uid}
        if displayname is not None:
            self._cfgstore['users'][name]['displayname'] = displayname
        if 'idmap' not in _cfgstore['main']:
            _cfgstore['main']['idmap'] = {}
        _cfgstore['main']['idmap'][uid] = {
            'tenant': self.tenant,
            'username': name
        }
        if attributemap is not None:
            self.set_user(name, attributemap)
        _mark_dirtykey('users', name, self.tenant)
        _mark_dirtykey('idmap', uid)
        self._bg_sync_to_file()

    def is_node(self, node):
        return node in self._cfgstore['nodes']

    def is_nodegroup(self, nodegroup):
        return nodegroup in self._cfgstore['groups']

    def get_groups(self):
        return self._cfgstore['groups'].iterkeys()

    def list_nodes(self):
        try:
            return self._cfgstore['nodes'].iterkeys()
        except KeyError:
            return []

    def get_nodegroup_attributes(self, nodegroup, attributes=()):
        cfgnodeobj = self._cfgstore['groups'][nodegroup]
        if not attributes:
            attributes = cfgnodeobj.iterkeys()
        nodeobj = {}
        for attribute in attributes:
            if attribute.startswith('_'):
                continue
            if attribute not in cfgnodeobj:
                continue
            nodeobj[attribute] = _decode_attribute(attribute, cfgnodeobj,
                                                   decrypt=self.decrypt)
        return nodeobj

    def get_node_attributes(self, nodelist, attributes=()):
        retdict = {}
        if isinstance(nodelist, str) or isinstance(nodelist, unicode):
            nodelist = [nodelist]
        for node in nodelist:
            if node not in self._cfgstore['nodes']:
                continue
            cfgnodeobj = self._cfgstore['nodes'][node]
            nodeobj = {}
            if len(attributes) == 0:
                attributes = cfgnodeobj.iterkeys()
            for attribute in attributes:
                if attribute.startswith('_'):
                    # skip private things
                    continue
                if attribute not in cfgnodeobj:
                    continue
                # since the formatter is not passed in, the calculator is
                # skipped.  The decryption, however, we want to do only on
                # demand
                nodeobj[attribute] = _decode_attribute(attribute, cfgnodeobj,
                                                       decrypt=self.decrypt)
            retdict[node] = nodeobj
        return retdict

    def _node_added_to_group(self, node, group, changeset):
        try:
            nodecfg = self._cfgstore['nodes'][node]
            groupcfg = self._cfgstore['groups'][group]
        except KeyError:  # something did not exist, nothing to do
            return
        for attrib in groupcfg.iterkeys():
            self._do_inheritance(nodecfg, attrib, node, changeset)
            _addchange(changeset, node, attrib)

    def _node_removed_from_group(self, node, group, changeset):
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
                    self._do_inheritance(nodecfg, attrib, node, changeset)
                    _addchange(changeset, node, attrib)
                    _mark_dirtykey('nodes', node, self.tenant)
            except KeyError:  # inheritedfrom not set, move on
                pass

    def _do_inheritance(self, nodecfg, attrib, nodename, changeset,
                        srcgroup=None):
        # for now, just do single inheritance
        # TODO: concatenating inheritance if requested
        if attrib in ('nodes', 'groups'):
            #not attributes that should be considered here
            return
        if attrib in nodecfg and 'inheritedfrom' not in nodecfg[attrib]:
            return  # already has a non-inherited value set, nothing to do
        # if the attribute is not set, this will search for a candidate
        # if it is set, but inheritedfrom, search for a replacement, just
        # in case
        if not 'groups' in nodecfg:
            return
        for group in nodecfg['groups']:
            if attrib in self._cfgstore['groups'][group]:
                if srcgroup is not None and group != srcgroup:
                    # skip needless deepcopy
                    return
                nodecfg[attrib] = \
                    copy.deepcopy(self._cfgstore['groups'][group][attrib])
                nodecfg[attrib]['inheritedfrom'] = group
                self._refresh_nodecfg(nodecfg, attrib, nodename,
                                      changeset=changeset)
                _mark_dirtykey('nodes', nodename, self.tenant)
                return
            if srcgroup is not None and group == srcgroup:
                # break out
                return

    def _sync_groups_to_node(self, groups, node, changeset):
        for group in self._cfgstore['groups'].iterkeys():
            if group not in groups:
                if node in self._cfgstore['groups'][group]['nodes']:
                    self._cfgstore['groups'][group]['nodes'].discard(node)
                    self._node_removed_from_group(node, group, changeset)
                    _mark_dirtykey('groups', group, self.tenant)
        for group in groups:
            if group not in self._cfgstore['groups']:
                self._cfgstore['groups'][group] = {'nodes': set([node])}
                _mark_dirtykey('groups', group, self.tenant)
            elif node not in self._cfgstore['groups'][group]['nodes']:
                self._cfgstore['groups'][group]['nodes'].add(node)
                _mark_dirtykey('groups', group, self.tenant)
            # node was not already in given group, perform inheritence fixup
            self._node_added_to_group(node, group, changeset)

    def _sync_nodes_to_group(self, nodes, group, changeset):
        for node in self._cfgstore['nodes'].iterkeys():
            if node not in nodes and 'groups' in self._cfgstore['nodes'][node]:
                if group in self._cfgstore['nodes'][node]['groups']:
                    self._cfgstore['nodes'][node]['groups'].remove(group)
                    self._node_removed_from_group(node, group, changeset)
        for node in nodes:
            if node not in self._cfgstore['nodes']:
                self._cfgstore['nodes'][node] = {'groups': [group]}
                _mark_dirtykey('nodes', node, self.tenant)
            elif group not in self._cfgstore['nodes'][node]['groups']:
                self._cfgstore['nodes'][node]['groups'].insert(0, group)
                _mark_dirtykey('nodes', node, self.tenant)
            else:
                continue  # next node, this node already in
            self._node_added_to_group(node, group, changeset)

    def add_group_attributes(self, attribmap):
        self.set_group_attributes(attribmap, autocreate=True)

    def set_group_attributes(self, attribmap, autocreate=False):
        changeset = {}
        for group in attribmap.iterkeys():
            if not autocreate and group not in self._cfgstore['groups']:
                raise ValueError("{0} group does not exist".format(group))
            for attr in attribmap[group].iterkeys():
                if (attr != 'nodes' and
                        (attr not in allattributes.node or
                         ('type' in allattributes.node[attr] and
                          not isinstance(attribmap[group][attr],
                                         allattributes.node[attr]['type'])))):
                    raise ValueError
                if attr == 'nodes':
                    if not isinstance(attribmap[group][attr], list):
                        raise ValueError(
                            "nodes attribute on group must be list")
                    for node in attribmap[group]['nodes']:
                        if node not in self._cfgstore['nodes']:
                            raise ValueError(
                                "{0} node does not exist to add to {1}".format(
                                    node, group))
        for group in attribmap.iterkeys():
            group = group.encode('utf-8')
            if group not in self._cfgstore['groups']:
                self._cfgstore['groups'][group] = {'nodes': set()}
            cfgobj = self._cfgstore['groups'][group]
            for attr in attribmap[group].iterkeys():
                if attr == 'nodes':
                    newdict = set(attribmap[group][attr])
                elif (isinstance(attribmap[group][attr], str) or
                        isinstance(attribmap[group][attr], unicode)):
                    newdict = {'value': attribmap[group][attr]}
                else:
                    newdict = attribmap[group][attr]
                if 'value' in newdict and attr.startswith("secret."):
                    newdict['cryptvalue'] = crypt_value(newdict['value'])
                    del newdict['value']
                cfgobj[attr] = newdict
                if attr == 'nodes':
                    self._sync_nodes_to_group(group=group,
                                              nodes=attribmap[group]['nodes'],
                                              changeset=changeset)
                else:  # update inheritence
                    for node in cfgobj['nodes']:
                        nodecfg = self._cfgstore['nodes'][node]
                        self._do_inheritance(nodecfg, attr, node, changeset,
                                             srcgroup=group)
                        _addchange(changeset, node, attr)
            _mark_dirtykey('groups', group, self.tenant)
        self._notif_attribwatchers(changeset)
        self._bg_sync_to_file()

    def clear_group_attributes(self, groups, attributes):
        changeset = {}
        if type(groups) in (str, unicode):
            groups = (groups,)
        for group in groups:
                group = group.encode('utf-8')
                try:
                    groupentry = self._cfgstore['groups'][group]
                except KeyError:
                    continue
                for attrib in attributes:
                    if attrib == 'nodes':
                        groupentry['nodes'] = set()
                        self._sync_nodes_to_group(
                            group=group, nodes=(), changeset=changeset)
                    else:
                        try:
                            del groupentry[attrib]
                        except KeyError:
                            pass
                        for node in groupentry['nodes']:
                            nodecfg = self._cfgstore['nodes'][node]
                            try:
                                delnodeattrib = (
                                    nodecfg[attrib]['inheritedfrom'] == group)
                            except KeyError:
                                delnodeattrib = False
                            if delnodeattrib:
                                del nodecfg[attrib]
                                self._do_inheritance(nodecfg, attrib, node,
                                                     changeset)
                                _addchange(changeset, node, attrib)
                                _mark_dirtykey('nodes', node, self.tenant)
                _mark_dirtykey('groups', group, self.tenant)
        self._notif_attribwatchers(changeset)
        self._bg_sync_to_file()

    def _refresh_nodecfg(self, cfgobj, attrname, node, changeset):
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
            self._recalculate_expressions(cfgobj, formatter=exprmgr, node=node,
                                          changeset=changeset)

    def _notif_attribwatchers(self, nodeattrs):
        if self.tenant not in self._attribwatchers:
            return
        notifdata = {}
        attribwatchers = self._attribwatchers[self.tenant]
        for node in nodeattrs.iterkeys():
            if node not in attribwatchers:
                continue
            attribwatcher = attribwatchers[node]
            for attrname in nodeattrs[node].iterkeys():
                if attrname not in attribwatcher:
                    continue
                for notifierid in attribwatcher[attrname].iterkeys():
                    if notifierid in notifdata:
                        if node in notifdata[notifierid]['nodeattrs']:
                            notifdata[notifierid]['nodeattrs'][node].append(
                                attrname)
                        else:
                            notifdata[notifierid]['nodeattrs'][node] = [
                                attrname]
                    else:
                        notifdata[notifierid] = {
                            'nodeattrs': {node: [attrname]},
                            'callback': attribwatcher[attrname][notifierid]
                        }
        for watcher in notifdata.itervalues():
            callback = watcher['callback']
            callback(nodeattribs=watcher['nodeattrs'], configmanager=self)

    def del_nodes(self, nodes):
        if self.tenant in self._nodecollwatchers:
            for watcher in self._nodecollwatchers[self.tenant].itervalues():
                watcher(added=[], deleting=nodes, configmanager=self)
        changeset = {}
        for node in nodes:
            node = node.encode('utf-8')
            if node in self._cfgstore['nodes']:
                self._sync_groups_to_node(node=node, groups=[],
                                          changeset=changeset)
                del self._cfgstore['nodes'][node]
                _mark_dirtykey('nodes', node, self.tenant)
        self._notif_attribwatchers(changeset)
        self._bg_sync_to_file()

    def del_groups(self, groups):
        changeset = {}
        for group in groups:
            if group in self._cfgstore['groups']:
                self._sync_nodes_to_group(group=group, nodes=[],
                                          changeset=changeset)
                del self._cfgstore['groups'][group]
                _mark_dirtykey('groups', group, self.tenant)
        self._notif_attribwatchers(changeset)
        self._bg_sync_to_file()

    def clear_node_attributes(self, nodes, attributes):
        # accumulate all changes into a changeset and push in one go
        changeset = {}
        for node in nodes:
            node = node.encode('utf-8')
            try:
                nodek = self._cfgstore['nodes'][node]
            except KeyError:
                continue
            recalcexpressions = False
            for attrib in attributes:
                if attrib in nodek and 'inheritedfrom' not in nodek[attrib]:
                    # if the attribute is set and not inherited,
                    # delete it and check for inheritence to backfil data
                    del nodek[attrib]
                    self._do_inheritance(nodek, attrib, node, changeset)
                    _addchange(changeset, node, attrib)
                    _mark_dirtykey('nodes', node, self.tenant)
                if ('_expressionkeys' in nodek and
                        attrib in nodek['_expressionkeys']):
                    recalcexpressions = True
            if recalcexpressions:
                exprmgr = _ExpressionFormat(nodek, node)
                self._recalculate_expressions(nodek, formatter=exprmgr,
                                              node=node, changeset=changeset)
        self._notif_attribwatchers(changeset)
        self._bg_sync_to_file()

    def add_node_attributes(self, attribmap):
        for node in attribmap.iterkeys():
            if 'groups' not in attribmap[node]:
                attribmap[node]['groups'] = []
        self.set_node_attributes(attribmap, autocreate=True)

    def set_node_attributes(self, attribmap, autocreate=False):
        # TODO(jbjohnso): multi mgr support, here if we have peers,
        # pickle the arguments and fire them off in eventlet
        # flows to peers, all should have the same result
        newnodes = []
        changeset = {}
        # first do a sanity check of the input upfront
        # this mitigates risk of arguments being partially applied
        for node in attribmap.iterkeys():
            node = node.encode('utf-8')
            if autocreate is False and node not in self._cfgstore['nodes']:
                raise ValueError("node {0} does not exist".format(node))
            for attrname in attribmap[node].iterkeys():
                attrval = attribmap[node][attrname]
                if (attrname not in allattributes.node or
                        ('type' in allattributes.node[attrname] and
                         not isinstance(
                             attrval,
                             allattributes.node[attrname]['type']))):
                    errstr = "{0} attribute on node {1} is invalid".format(
                        attrname, node)
                    raise ValueError(errstr)
                if attrname == 'groups':
                    for group in attribmap[node]['groups']:
                        if group not in self._cfgstore['groups']:
                            raise ValueError(
                                "group {0} does not exist".format(group))
                    if ('everything' in self._cfgstore['groups'] and
                            'everything' not in attribmap[node]['groups']):
                        attribmap[node]['groups'].append('everything')
        for node in attribmap.iterkeys():
            node = node.encode('utf-8')
            exprmgr = None
            if node not in self._cfgstore['nodes']:
                newnodes.append(node)
                self._cfgstore['nodes'][node] = {}
            cfgobj = self._cfgstore['nodes'][node]
            recalcexpressions = False
            for attrname in attribmap[node].iterkeys():
                if (isinstance(attribmap[node][attrname], str) or
                        isinstance(attribmap[node][attrname], unicode)):
                    newdict = {'value': attribmap[node][attrname]}
                else:
                    newdict = attribmap[node][attrname]
                if 'value' in newdict and attrname.startswith("secret."):
                    newdict['cryptvalue'] = crypt_value(newdict['value'])
                    del newdict['value']
                cfgobj[attrname] = newdict
                if attrname == 'groups':
                    self._sync_groups_to_node(node=node,
                                              groups=attribmap[node]['groups'],
                                              changeset=changeset)
                if ('_expressionkeys' in cfgobj and
                        attrname in cfgobj['_expressionkeys']):
                    recalcexpressions = True
                if 'expression' in cfgobj[attrname]:  # evaluate now
                    if exprmgr is None:
                        exprmgr = _ExpressionFormat(cfgobj, node)
                    cfgobj[attrname] = _decode_attribute(attrname, cfgobj,
                                                         formatter=exprmgr)
                # if any code is watching these attributes, notify
                # them of the change
                _addchange(changeset, node, attrname)
                _mark_dirtykey('nodes', node, self.tenant)
            if recalcexpressions:
                if exprmgr is None:
                    exprmgr = _ExpressionFormat(cfgobj, node)
                self._recalculate_expressions(cfgobj, formatter=exprmgr,
                                              node=node, changeset=changeset)
        self._notif_attribwatchers(changeset)
        if newnodes:
            if self.tenant in self._nodecollwatchers:
                nodecollwatchers = self._nodecollwatchers[self.tenant]
                for watcher in nodecollwatchers.itervalues():
                    watcher(added=newnodes, deleting=[], configmanager=self)
        self._bg_sync_to_file()
        #TODO: wait for synchronization to suceed/fail??)

    @classmethod
    def _read_from_path(cls):
        global _cfgstore
        _cfgstore = {}
        rootpath = cls._cfgdir
        _load_dict_from_dbm(['globals'], rootpath + "/globals")
        _load_dict_from_dbm(['main', 'nodes'], rootpath + "/nodes")
        _load_dict_from_dbm(['main', 'users'], rootpath + "/users")
        _load_dict_from_dbm(['main', 'groups'], rootpath + "/groups")
        try:
            for tenant in os.listdir(rootpath + '/tenants/'):
                _load_dict_from_dbm(
                    ['main', tenant, 'nodes'],
                    "%s/%s/nodes" % (rootpath, tenant))
                _load_dict_from_dbm(
                    ['main', tenant, 'groups'],
                    "%s/%s/groups" % (rootpath, tenant))
                _load_dict_from_dbm(
                    ['main', tenant, 'users'],
                    "%s/%s/users" % (rootpath, tenant))
        except OSError:
            pass

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
        if 'dirtyglobals' in _cfgstore:
            with _dirtylock:
                dirtyglobals = copy.deepcopy(_cfgstore['dirtyglobals'])
                del _cfgstore['dirtyglobals']
            _mkpath(cls._cfgdir)
            globalf = dbm.open(cls._cfgdir + "/globals", 'c', 384)  # 0600
            for globalkey in dirtyglobals:
                if globalkey in _cfgstore['globals']:
                    globalf[globalkey] = \
                        cPickle.dumps(_cfgstore['globals'][globalkey])
                else:
                    if globalkey in globalf:
                        del globalf[globalkey]
            globalf.close()
        if 'dirtykeys' in _cfgstore:
            with _dirtylock:
                currdirt = copy.deepcopy(_cfgstore['dirtykeys'])
                del _cfgstore['dirtykeys']
            for tenant in currdirt.iterkeys():
                dkdict = currdirt[tenant]
                if tenant is None:
                    pathname = cls._cfgdir
                    currdict = _cfgstore['main']
                else:
                    pathname = cls._cfgdir + '/tenants/' + tenant + '/'
                    currdict = _cfgstore['tenant'][tenant]
                for category in dkdict.iterkeys():
                    _mkpath(pathname)
                    dbf = dbm.open(pathname + category, 'c', 384)  # 0600 mode
                    for ck in dkdict[category]:
                        if ck not in currdict[category]:
                            if ck in dbf:
                                del dbf[ck]
                        else:
                            dbf[ck] = cPickle.dumps(currdict[category][ck])
        if cls._writepending:
            cls._writepending = False
            return cls._sync_to_file()

    def _recalculate_expressions(self, cfgobj, formatter, node, changeset):
        for key in cfgobj.iterkeys():
            if not isinstance(cfgobj[key], dict):
                continue
            if 'expression' in cfgobj[key]:
                cfgobj[key] = _decode_attribute(key, cfgobj,
                                                formatter=formatter)
                _addchange(changeset, node, key)
            elif ('cryptvalue' not in cfgobj[key] and
                    'value' not in cfgobj[key]):
                # recurse for nested structures, with some hint that
                # it might indeed be a nested structure
                self._recalculate_expressions(cfgobj[key], formatter, node,
                                              changeset)


try:
    ConfigManager._read_from_path()
except IOError:
    _cfgstore = {}


# some unit tests worth implementing:
# set group attribute on lower priority group, result is that node should not
# change
# after that point, then unset on the higher priority group, lower priority
# group should get it then
# rinse and repeat for set on node versus set on group
# clear group attribute and assure than it becomes unset on all nodes
# set various expressions