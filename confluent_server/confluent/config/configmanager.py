# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 IBM Corporation
# Copyright 2015-2018 Lenovo
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
import base64
import confluent.config.attributes as allattributes
import confluent.config.conf as conf
import confluent.log
import confluent.noderange as noderange
import confluent.util
import confluent.netutil as netutil
import confluent.exceptions as exc
import copy
import cPickle
import errno
import eventlet
import fnmatch
import json
import operator
import os
import random
import re
import string
import sys
import threading
import traceback


_masterkey = None
_masterintegritykey = None
_dirtylock = threading.RLock()
_config_areas = ('nodegroups', 'nodes', 'usergroups', 'users')
tracelog = None
statelessmode = False
_cfgstore = None

_attraliases = {
    'bmc': 'hardwaremanagement.manager',
    'bmcuser': 'secret.hardwaremanagementuser',
    'bmcpass': 'secret.hardwaremanagementpassword',
}

def _mkpath(pathname):
    try:
        os.makedirs(pathname)
    except OSError as e:
        if e.errno == errno.EEXIST and os.path.isdir(pathname):
            pass
        else:
            raise


def _derive_keys(password, salt):
    #implement our specific combination of pbkdf2 transforms to get at
    #key.  We bump the iterations up because we can afford to
    #TODO: WORKERPOOL PBKDF2 is expensive
    tmpkey = KDF.PBKDF2(password, salt, 32, 50000,
                        lambda p, s: HMAC.new(p, s, SHA256).digest())
    finalkey = KDF.PBKDF2(tmpkey, salt, 32, 50000,
                          lambda p, s: HMAC.new(p, s, SHA256).digest())
    return finalkey[:16], finalkey[16:]


def _get_protected_key(keydict, password, paramname):
    if password and 'unencryptedvalue' in keydict:
        set_global(paramname, _format_key(
            keydict['unencryptedvalue'],
            password=password))
    if 'unencryptedvalue' in keydict:
        return keydict['unencryptedvalue']
    # TODO(jbjohnso): check for TPM sealing
    if 'passphraseprotected' in keydict:
        if password is None:
            raise exc.LockedCredentials("Passphrase protected secret requires password")
        pp = keydict['passphraseprotected']
        salt = pp[0]
        privkey, integkey = _derive_keys(password, salt)
        return decrypt_value(pp[1:], key=privkey, integritykey=integkey)
    else:
        raise exc.LockedCredentials("No available decryption key")


def _parse_key(keydata, password=None):
    if keydata.startswith('*unencrypted:'):
        return base64.b64decode(keydata[13:])
    elif password:
        salt, iv, crypt, hmac = [base64.b64decode(x)
                                 for x in keydata.split('!')]
        privkey, integkey = _derive_keys(password, salt)
        return decrypt_value([iv, crypt, hmac], privkey, integkey)
    raise(exc.LockedCredentials(
        "Passphrase protected secret requires password"))


def _format_key(key, password=None):
    if password is not None:
        salt = os.urandom(32)
        privkey, integkey = _derive_keys(password, salt)
        cval = crypt_value(key, key=privkey, integritykey=integkey)
        return {"passphraseprotected": (salt,) + cval}
    else:
        return {"unencryptedvalue": key}


def _do_notifier(cfg, watcher, callback):
    try:
        callback(nodeattribs=watcher['nodeattrs'], configmanager=cfg)
    except Exception:
        logException()


def logException():
    global tracelog
    if tracelog is None:
        tracelog = confluent.log.Logger('trace')
    tracelog.log(traceback.format_exc(),
                 ltype=confluent.log.DataTypes.event,
                 event=confluent.log.Events.stacktrace)


def _do_add_watcher(watcher, added, configmanager):
    try:
        watcher(added=added, deleting=[], configmanager=configmanager)
    except Exception:
        logException()


def init_masterkey(password=None):
    global _masterkey
    global _masterintegritykey
    cfgn = get_global('master_privacy_key')

    if cfgn:
        _masterkey = _get_protected_key(cfgn, password, 'master_privacy_key')
    else:
        _masterkey = os.urandom(32)
        set_global('master_privacy_key', _format_key(
            _masterkey,
            password=password))
    cfgn = get_global('master_integrity_key')
    if cfgn:
        _masterintegritykey = _get_protected_key(cfgn, password,
                                                 'master_integrity_key')
    else:
        _masterintegritykey = os.urandom(64)
        set_global('master_integrity_key', _format_key(
            _masterintegritykey,
            password=password))


def decrypt_value(cryptvalue,
                  key=None,
                  integritykey=None):
    iv, cipherdata, hmac = cryptvalue
    if key is None and integritykey is None:
        if _masterkey is None or _masterintegritykey is None:
            init_masterkey()
        key = _masterkey
        integritykey = _masterintegritykey
    check_hmac = HMAC.new(integritykey, cipherdata, SHA256).digest()
    if hmac != check_hmac:
        raise Exception("bad HMAC value on crypted value")
    decrypter = AES.new(key, AES.MODE_CBC, iv)
    value = decrypter.decrypt(cipherdata)
    padsize = ord(value[-1])
    pad = value[-padsize:]
    # Note that I cannot grasp what could be done with a subliminal
    # channel in padding in this case, but check the padding anyway
    for padbyte in pad:
        if ord(padbyte) != padsize:
            raise Exception("bad padding in encrypted value")
    return value[0:-padsize]


def fixup_attribute(attrname, attrval):
    # Normalize some data, for example strings and numbers to bool
    attrname = _get_valid_attrname(attrname)
    if attrname not in allattributes.node:  # no fixup possible
        return attrval
    if 'type' in allattributes.node[attrname] and not isinstance(attrval, allattributes.node[attrname]['type']):
        if (allattributes.node[attrname]['type'] == bool and
                (isinstance(attrval, str) or isinstance(attrval, unicode))):
            return attrval.lower() in ('true', '1', 'y', 'yes', 'enable', 'enabled')
    return attrval


def attribute_is_invalid(attrname, attrval):
    if attrname.startswith('custom.'):
        # No type checking or name checking is provided for custom,
        # it's not possible
        return False
    attrname = _get_valid_attrname(attrname)
    if attrname not in allattributes.node:
        # Otherwise, it must be in the allattributes key list
        return True
    if 'type' in allattributes.node[attrname]:
        if not isinstance(attrval, allattributes.node[attrname]['type']):
            # it is valid if it is {'value': actualvalue}
            if (isinstance(attrval, dict) and 'value' in attrval and
                    isinstance(attrval['value'],
                               allattributes.node[attrname]['type'])):
                return False
            # provide type checking for attributes with a specific type
            return True
    return False


def _get_valid_attrname(attrname):
    if attrname.startswith('net.'):
        # For net.* attribtues, split on the dots and put back together
        # longer term we might want a generic approach, but
        # right now it's just net. attributes
        netattrparts = attrname.split('.')
        attrname = netattrparts[0] + '.' + netattrparts[-1]
    return attrname


def crypt_value(value,
                key=None,
                integritykey=None):
    # encrypt given value
    # PKCS7 is the padding scheme to employ, if no padded needed, pad with 16
    # check HMAC prior to attempting decrypt
    if key is None or integritykey is None:
        if _masterkey is None or _masterintegritykey is None:
            init_masterkey()
        key = _masterkey
        integritykey = _masterintegritykey
    iv = os.urandom(16)
    crypter = AES.new(key, AES.MODE_CBC, iv)
    neededpad = 16 - (len(value) % 16)
    pad = chr(neededpad) * neededpad
    value += pad
    try:
        cryptval = crypter.encrypt(value)
    except TypeError:
        cryptval = crypter.encrypt(value.encode('utf-8'))
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
        try:
            for tk in dbe:
                currdict[tk] = cPickle.loads(dbe[tk])
        except AttributeError:
            tk = dbe.firstkey()
            while tk != None:
                currdict[tk] = cPickle.loads(dbe[tk])
                tk = dbe.nextkey(tk)
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
    if _cfgstore is None:
        init()
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
    if _cfgstore is None:
        init()
    with _dirtylock:
        if 'dirtyglobals' not in _cfgstore:
            _cfgstore['dirtyglobals'] = set()
        _cfgstore['dirtyglobals'].add(globalname)
    if 'globals' not in _cfgstore:
        _cfgstore['globals'] = {globalname: value}
    else:
        _cfgstore['globals'][globalname] = value
    ConfigManager._bg_sync_to_file()

cfgstreams = {}
def register_config_listener(name, listener):
    cfgstreams[listener] = name

def add_collective_member(name, address, fingerprint):
    try:
        name = name.encode('utf-8')
    except AttributeError:
        pass
    if _cfgstore is None:
        init()
    if 'collective' not in _cfgstore:
        _cfgstore['collective'] = {}
    _cfgstore['collective'][name] = {'name': name, 'address': address,
                                     'fingerprint': fingerprint}
    with _dirtylock:
        if 'collectivedirty' not in _cfgstore:
            _cfgstore['collectivedirty'] = set([])
        _cfgstore['collectivedirty'].add(name)
    ConfigManager._bg_sync_to_file()

def get_collective_member(name):
    return _cfgstore['collective'][name]


def get_collective_member_by_address(address):
    for name in _cfgstore.get('collective', {}):
        currdrone = _cfgstore['collective'][name]
        if netutil.addresses_match(address, currdrone['address']):
            return currdrone


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
    # generate a random id outside the usual ranges used for normal users in
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
            left = node
            key = ''
            while isinstance(left, ast.Attribute):
                # Loop through, to handle multi dot expressions
                # such as 'net.pxe.hwaddr'
                key = '.' + left.attr + key
                left = left.value
            key = left.id + key
            if (not key.startswith('custom.') and
                        _get_valid_attrname(key) not in allattributes.node):
                raise ValueError(
                    '{0} is not a valid attribute name'.format(key))
            val = self._expand_attribute(key)
            return val['value'] if val and 'value' in val else ""
        elif isinstance(node, ast.Name):
            var = node.id
            if var in ('node', 'nodename'):
                return self._nodename
            if var in _attraliases:
                val = self._expand_attribute(_attraliases[var])
                return val['value'] if 'value' in val else ""
            mg = re.match(self.posmatch, var)
            if mg:
                idx = int(mg.group(1))
                if self._numbers is None:
                    self._numbers = re.findall(self.nummatch, self._nodename)
                return int(self._numbers[idx - 1])
            else:
                if var in self._nodeobj:
                    val = self._expand_attribute(var)
                    return val['value'] if val and 'value' in val else ""
                elif (not var.startswith('custom.') and
                        _get_valid_attrname(var) not in allattributes.node):
                    raise ValueError(
                        '{0} is not a valid attribute name'.format(var))
        elif isinstance(node, ast.BinOp):
            optype = type(node.op)
            if optype not in self._supported_ops:
                raise Exception("Unsupported operation")
            op = self._supported_ops[optype]
            return op(int(self._handle_ast_node(node.left)),
                      int(self._handle_ast_node(node.right)))

    def _expand_attribute(self, key):
        if '_expressionkeys' not in self._nodeobj:
            self._nodeobj['_expressionkeys'] = set([key])
        else:
            self._nodeobj['_expressionkeys'].add(key)
        val = _decode_attribute(key, self._nodeobj,
                                formatter=self)
        return val


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
        for tenant in _cfgstore['tenant']:
            callback(ConfigManager(tenant))
    except KeyError:
        pass


class ConfigManager(object):
    if os.name == 'nt':
        _cfgdir = os.path.join(
            os.getenv('SystemDrive'), '\\ProgramData', 'confluent', 'cfg')
    else:
        _cfgdir = "/etc/confluent/cfg"
    _cfgwriter = None
    _writepending = False
    _syncrunning = False
    _syncstate = threading.RLock()
    _attribwatchers = {}
    _nodecollwatchers = {}
    _notifierids = {}

    def __init__(self, tenant, decrypt=False, username=None):
        global _cfgstore
        if _cfgstore is None:
            init()
        self.decrypt = decrypt
        self.current_user = username
        if tenant is None:
            self.tenant = None
            if 'main' not in _cfgstore:
                _cfgstore['main'] = {}
                self._bg_sync_to_file()
            self._cfgstore = _cfgstore['main']
            if 'nodegroups' not in self._cfgstore:
                self._cfgstore['nodegroups'] = {'everything': {'nodes': set()}}
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
        if 'nodegroups' not in self._cfgstore:
            self._cfgstore['nodegroups'] = {'everything': {}}
        if 'nodes' not in self._cfgstore:
            self._cfgstore['nodes'] = {}
        self._bg_sync_to_file()

    def filter_node_attributes(self, expression, nodes=None):
        """Filtered nodelist according to expression

        expression may be:
        attribute.name=value
        attribute.name==value
        attribute.name=~value
        attribute.name!=value
        attribute.name!~value

        == and != do strict equality.  The ~ operators do a regular expression.
        ! negates the sense of the match

        :param expression: The expression containing the criteria to match
        :param nodes: Optional iterable set of nodes to limit the check
        """
        exmatch = None
        yieldmatches = True
        if nodes is None:
            nodes = self._cfgstore['nodes']
        if '==' in expression:
            attribute, match = expression.split('==')
        elif '!=' in expression:
            attribute, match = expression.split('!=')
            yieldmatches = False
        elif '=~' in expression:
            attribute, match = expression.split('=~')
            exmatch = re.compile(match)
        elif '!~' in expression:
            attribute, match = expression.split('!~')
            exmatch = re.compile(match)
            yieldmatches = False
        elif '=' in expression:
            attribute, match = expression.split('=')
        else:
            raise Exception('Invalid Expression')
        for node in nodes:
            try:
                currval = self._cfgstore['nodes'][node][attribute]['value']
            except KeyError:
                # Let's treat 'not set' as being an empty string for this path
                currval = ''
            if exmatch:
                if yieldmatches:
                    if exmatch.search(currval):
                        yield node
                else:
                    if not exmatch.search(currval):
                        yield node
            else:
                if yieldmatches:
                    if match == currval:
                        yield node
                else:
                    if match != currval:
                        yield node

    def filter_nodenames(self, expression, nodes=None):
        """Filter nodenames by regular expression

        :param expression: Regular expression for matching nodenames
        :param nodes: Optional iterable of candidates
        """
        if nodes is None:
            nodes = self._cfgstore['nodes']
        expression = re.compile(expression)
        for node in nodes:
            if expression.search(node):
                yield node

    def watch_attributes(self, nodes, attributes, callback):
        """
        Watch a list of attributes for changes on a list of nodes.  The
        attributes may be literal, or a filename style wildcard like
        'net*.switch'

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
                if '*' in attribute:
                    currglobs = attribwatchers[node].get('_attrglobs', set([]))
                    currglobs.add(attribute)
                    attribwatchers[node]['_attrglobs'] = currglobs
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
            return list(self._cfgstore['users'])
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

    def get_usergroup(self, groupname):
        """Get user group information from DB

        :param groupname: Name of the group

        Returns a dictionary describing parameters of a user group.
        This may include the role for users in the group to receive
        if no more specific information is found.

        """
        try:
            return copy.deepcopy(self._cfgstore['usergroups'][groupname])
        except KeyError:
            return None

    def set_usergroup(self, groupname, attributemap):
        """Set usergroup attribute(s)

        :param groupname: the name of teh group to modify
        :param attributemap: The mapping of keys to values to set
        """

        for attribute in attributemap:
            self._cfgstore['usergroups'][attribute] = attributemap[attribute]
        _mark_dirtykey('usergroups', groupname, self.tenant)

    def create_usergroup(self, groupname, role="Administrator"):
        if 'usergroups' not in self._cfgstore:
            self._cfgstore['usergroups'] = {}
        groupname = groupname.encode('utf-8')
        if groupname in self._cfgstore['usergroups']:
            raise Exception("Duplicate groupname requested")
        self._cfgstore['usergroups'][groupname] = {'role': role}
        _mark_dirtykey('usergroups', groupname, self.tenant)

    def set_user(self, name, attributemap):
        """Set user attribute(s)

        :param name: The login name of the user
        :param attributemap: A dict of key values to set
        """
        user = self._cfgstore['users'][name]
        for attribute in attributemap:
            if attribute == 'password':
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
        if 'idmap' not in _cfgstore['main']:
            _cfgstore['main']['idmap'] = {}
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
        return nodegroup in self._cfgstore['nodegroups']

    def get_groups(self, sizesort=False):
        if sizesort:
            return reversed(
                sorted(self._cfgstore['nodegroups'], key=lambda x: len(
                    self._cfgstore['nodegroups'][x]['nodes'])))
        return iter(self._cfgstore['nodegroups'])

    def list_nodes(self):
        try:
            return iter(self._cfgstore['nodes'])
        except KeyError:
            return []

    def get_nodegroup_attributes(self, nodegroup, attributes=()):
        cfgnodeobj = self._cfgstore['nodegroups'][nodegroup]
        if not attributes:
            attributes = cfgnodeobj
        nodeobj = {}
        for attribute in attributes:
            if attribute.startswith('_'):
                continue
            if attribute not in cfgnodeobj:
                continue
            nodeobj[attribute] = _decode_attribute(attribute, cfgnodeobj,
                                                   decrypt=self.decrypt)
        return nodeobj

    def expand_attrib_expression(self, nodelist, expression):
        if type(nodelist) in (unicode, str):
            nodelist = (nodelist,)
        for node in nodelist:
            cfgobj = self._cfgstore['nodes'][node]
            fmt = _ExpressionFormat(cfgobj, node)
            yield (node, fmt.format(expression))

    def get_node_attributes(self, nodelist, attributes=(), decrypt=None):
        if decrypt is None:
            decrypt = self.decrypt
        retdict = {}
        if isinstance(nodelist, str) or isinstance(nodelist, unicode):
            nodelist = [nodelist]
        if isinstance(attributes, str) or isinstance(attributes, unicode):
            attributes = [attributes]
        relattribs = attributes
        for node in nodelist:
            if node not in self._cfgstore['nodes']:
                continue
            cfgnodeobj = self._cfgstore['nodes'][node]
            nodeobj = {}
            if len(attributes) == 0:
                relattribs = cfgnodeobj
            for attribute in relattribs:
                if attribute.startswith('_'):
                    # skip private things
                    continue
                if '*' in attribute:
                    for attr in fnmatch.filter(list(cfgnodeobj), attribute):
                        nodeobj[attr] = _decode_attribute(attr, cfgnodeobj,
                                                          decrypt=decrypt)
                if attribute not in cfgnodeobj:
                    continue
                # since the formatter is not passed in, the calculator is
                # skipped.  The decryption, however, we want to do only on
                # demand
                nodeobj[attribute] = _decode_attribute(attribute, cfgnodeobj,
                                                       decrypt=decrypt)
            retdict[node] = nodeobj
        return retdict

    def _node_added_to_group(self, node, group, changeset):
        try:
            nodecfg = self._cfgstore['nodes'][node]
            groupcfg = self._cfgstore['nodegroups'][group]
        except KeyError:  # something did not exist, nothing to do
            return
        for attrib in groupcfg:
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
            if attrib in self._cfgstore['nodegroups'][group]:
                if srcgroup is not None and group != srcgroup:
                    # skip needless deepcopy
                    return
                nodecfg[attrib] = \
                    copy.deepcopy(self._cfgstore['nodegroups'][group][attrib])
                nodecfg[attrib]['inheritedfrom'] = group
                self._refresh_nodecfg(nodecfg, attrib, nodename,
                                      changeset=changeset)
                _mark_dirtykey('nodes', nodename, self.tenant)
                return
            if srcgroup is not None and group == srcgroup:
                # break out
                return

    def _sync_groups_to_node(self, groups, node, changeset):
        for group in self._cfgstore['nodegroups']:
            if group not in groups:
                if node in self._cfgstore['nodegroups'][group]['nodes']:
                    self._cfgstore['nodegroups'][group]['nodes'].discard(node)
                    self._node_removed_from_group(node, group, changeset)
                    _mark_dirtykey('nodegroups', group, self.tenant)
        for group in groups:
            if group not in self._cfgstore['nodegroups']:
                self._cfgstore['nodegroups'][group] = {'nodes': set([node])}
                _mark_dirtykey('nodegroups', group, self.tenant)
            elif node not in self._cfgstore['nodegroups'][group]['nodes']:
                self._cfgstore['nodegroups'][group]['nodes'].add(node)
                _mark_dirtykey('nodegroups', group, self.tenant)
            # node was not already in given group, perform inheritence fixup
            self._node_added_to_group(node, group, changeset)

    def _sync_nodes_to_group(self, nodes, group, changeset):
        for node in self._cfgstore['nodes']:
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
        for group in attribmap:
            if group == '':
                raise ValueError('"{0}" is not a valid group name'.format(
                    group))
            if autocreate:
                try:
                    noderange._parser.parseString(
                        '({0})'.format(group)).asList()
                except noderange.pp.ParseException as pe:
                    raise ValueError('"{0}" is not a valid group name'.format(
                        group))
            if not autocreate and group not in self._cfgstore['nodegroups']:
                raise ValueError("{0} group does not exist".format(group))
            for attr in attribmap[group]:
                # first do a pass to normalize out any aliased attribute names
                if attr in _attraliases:
                    newattr = _attraliases[attr]
                    attribmap[group][newattr] = attribmap[group][attr]
                    del attribmap[group][attr]
            for attr in attribmap[group]:
                if attr in _attraliases:
                    newattr = _attraliases[attr]
                    attribmap[group][newattr] = attribmap[group][attr]
                    del attribmap[group][attr]
                if attr not in ('nodes', 'noderange'):
                    attrval = fixup_attribute(attr, attribmap[group][attr])
                    if attribute_is_invalid(attr, attrval):
                        errstr = "{0} attribute is invalid".format(attr)
                        raise ValueError(errstr)
                    attribmap[group][attr] = attrval
                if attr == 'nodes':
                    if isinstance(attribmap[group][attr], dict):
                        currnodes = list(self.get_nodegroup_attributes(
                            group, ['nodes']).get('nodes', []))
                        if attribmap[group][attr].get('prepend', False):
                            newnodes = attribmap[group][attr][
                                'prepend'].split(',')
                            attribmap[group][attr] = newnodes + currnodes
                        elif attribmap[group][attr].get('remove', False):
                            delnodes = attribmap[group][attr][
                                'remove'].split(',')
                            attribmap[group][attr] = [
                                x for x in currnodes if x not in delnodes]
                    if not isinstance(attribmap[group][attr], list):
                        if type(attribmap[group][attr]) is unicode or type(attribmap[group][attr]) is str:
                            attribmap[group][attr]=attribmap[group][attr].split(",")
                        else:
                            raise ValueError("nodes attribute on group must be list")
                    for node in attribmap[group]['nodes']:
                        if node not in self._cfgstore['nodes']:
                            raise ValueError(
                                "{0} node does not exist to add to {1}".format(
                                    node, group))
        for group in attribmap:
            group = group.encode('utf-8')
            if group not in self._cfgstore['nodegroups']:
                self._cfgstore['nodegroups'][group] = {'nodes': set()}
            cfgobj = self._cfgstore['nodegroups'][group]
            for attr in attribmap[group]:
                if attr == 'nodes':
                    newdict = set(attribmap[group][attr])
                elif (isinstance(attribmap[group][attr], str) or
                        isinstance(attribmap[group][attr], unicode) or
                        isinstance(attribmap[group][attr], bool)):
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
                elif attr != 'noderange':  # update inheritence
                    for node in cfgobj['nodes']:
                        nodecfg = self._cfgstore['nodes'][node]
                        self._do_inheritance(nodecfg, attr, node, changeset,
                                             srcgroup=group)
                        _addchange(changeset, node, attr)
            _mark_dirtykey('nodegroups', group, self.tenant)
        self._notif_attribwatchers(changeset)
        self._bg_sync_to_file()

    def clear_group_attributes(self, groups, attributes):
        changeset = {}
        realattributes = []
        for attrname in list(attributes):
            if attrname in _attraliases:
                realattributes.append(_attraliases[attrname])
            else:
                realattributes.append(attrname)
        attributes = realattributes
        if type(groups) in (str, unicode):
            groups = (groups,)
        for group in groups:
                group = group.encode('utf-8')
                try:
                    groupentry = self._cfgstore['nodegroups'][group]
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
                _mark_dirtykey('nodegroups', group, self.tenant)
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
        for node in nodeattrs:
            if node not in attribwatchers:
                continue
            attribwatcher = attribwatchers[node]
            # usually, we will only look at the specific attribute keys that
            # have had change flagged, so set up to iterate through only those
            checkattrs = nodeattrs[node]
            if '_nodedeleted' in nodeattrs[node]:
                # in the case of a deleted node, we want to iterate through
                # *all* attributes that the node might have had set prior
                # to deletion, to make all watchers aware of the removed
                # node and take appropriate action
                checkattrs = attribwatcher
            globattrs = {}
            for attrglob in attribwatcher.get('_attrglobs', []):
                for matched in fnmatch.filter(list(checkattrs), attrglob):
                    globattrs[matched] = attrglob
            for attrname in checkattrs:
                if attrname == '_attrglobs':
                    continue
                watchkey = attrname
                # the attrib watcher could still have a glob
                if attrname not in attribwatcher:
                    if attrname in globattrs:
                        watchkey = globattrs[attrname]
                    else:
                        continue
                for notifierid in attribwatcher[watchkey]:
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
                            'callback': attribwatcher[watchkey][notifierid]
                        }
        for watcher in notifdata.itervalues():
            callback = watcher['callback']
            eventlet.spawn_n(_do_notifier, self, watcher, callback)


    def del_nodes(self, nodes):
        if self.tenant in self._nodecollwatchers:
            for watcher in self._nodecollwatchers[self.tenant].itervalues():
                watcher(added=[], deleting=nodes, configmanager=self)
        changeset = {}
        for node in nodes:
            # set a reserved attribute for the sake of the change notification
            # framework to trigger on
            changeset[node] = {'_nodedeleted': 1}
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
            if group in self._cfgstore['nodegroups']:
                self._sync_nodes_to_group(group=group, nodes=[],
                                          changeset=changeset)
                del self._cfgstore['nodegroups'][group]
                _mark_dirtykey('nodegroups', group, self.tenant)
        self._notif_attribwatchers(changeset)
        self._bg_sync_to_file()

    def clear_node_attributes(self, nodes, attributes):
        # accumulate all changes into a changeset and push in one go
        changeset = {}
        realattributes = []
        for attrname in list(attributes):
            if attrname in _attraliases:
                realattributes.append(_attraliases[attrname])
            else:
                realattributes.append(attrname)
        attributes = realattributes
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
        for node in attribmap:
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
        for node in attribmap:
            node = node.encode('utf-8')
            if node == '':
                raise ValueError('"{0}" is not a valid node name'.format(node))
            if autocreate:
                try:
                    noderange._parser.parseString(
                        '({0})'.format(node)).asList()
                except noderange.pp.ParseException as pe:
                    raise ValueError(
                        '"{0}" is not a valid node name'.format(node))
            if autocreate is False and node not in self._cfgstore['nodes']:
                raise ValueError("node {0} does not exist".format(node))
            for attrname in list(attribmap[node]):
                if attrname in _attraliases:
                    truename = _attraliases[attrname]
                    attribmap[node][truename] = attribmap[node][attrname]
                    del attribmap[node][attrname]
            for attrname in attribmap[node]:
                attrval = attribmap[node][attrname]
                try:
                    if (allattributes.node[attrname]['type'] == 'list' and
                            type(attrval) in (str, unicode)):
                        attrval = attrval.split(",")
                except KeyError:
                    pass
                if attrname == 'groups':
                    if isinstance(attribmap[node]['groups'], dict):
                        currgroups = self.get_node_attributes(
                            node, 'groups').get(node, {}).get('groups', [])
                        if attribmap[node]['groups'].get('prepend', False):
                            newgroups = attribmap[node]['groups'][
                                'prepend'].split(',')
                            attribmap[node]['groups'] = newgroups + currgroups
                        elif attribmap[node]['groups'].get('remove', False):
                            delgroups = attribmap[node]['groups'][
                                'remove'].split(',')
                            newgroups = [
                                x for x in currgroups if x not in delgroups]
                            attribmap[node]['groups'] = newgroups
                    elif type(attribmap[node]['groups']) != list:
                        attribmap[node]['groups']=attribmap[node]['groups'].split(",")
                    for group in attribmap[node]['groups']:
                        if group not in self._cfgstore['nodegroups']:
                            raise ValueError(
                                "group {0} does not exist".format(group))
                    if ('everything' in self._cfgstore['nodegroups'] and
                            'everything' not in attribmap[node]['groups']):
                        attribmap[node]['groups'].append('everything')
                else:
                    attrval = fixup_attribute(attrname, attrval)
                    if attribute_is_invalid(attrname, attrval):
                        errstr = "{0} attribute on node {1} is invalid".format(
                            attrname, node)
                        raise ValueError(errstr)
                    attribmap[node][attrname] = attrval
        for node in attribmap:
            node = node.encode('utf-8')
            exprmgr = None
            if node not in self._cfgstore['nodes']:
                newnodes.append(node)
                self._cfgstore['nodes'][node] = {}
            cfgobj = self._cfgstore['nodes'][node]
            recalcexpressions = False
            for attrname in attribmap[node]:
                if (isinstance(attribmap[node][attrname], str) or
                        isinstance(attribmap[node][attrname], unicode) or
                        isinstance(attribmap[node][attrname], bool)):
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
                    eventlet.spawn_n(_do_add_watcher, watcher, newnodes, self)
        self._bg_sync_to_file()
        #TODO: wait for synchronization to suceed/fail??)

    def _load_from_json(self, jsondata):
        """Load fresh configuration data from jsondata

        :param jsondata: String of jsondata
        :return:
        """
        dumpdata = json.loads(jsondata)
        tmpconfig = {}
        for confarea in _config_areas:
            if confarea not in dumpdata:
                continue
            tmpconfig[confarea] = {}
            for element in dumpdata[confarea]:
                newelement = copy.deepcopy(dumpdata[confarea][element])
                for attribute in dumpdata[confarea][element]:
                    if newelement[attribute] == '*REDACTED*':
                        raise Exception(
                            "Unable to restore from redacted backup")
                    elif attribute == 'cryptpass':
                        passparts = newelement[attribute].split('!')
                        newelement[attribute] = tuple([base64.b64decode(x)
                                                       for x in passparts])
                    elif 'cryptvalue' in newelement[attribute]:
                        bincrypt = newelement[attribute]['cryptvalue']
                        bincrypt = tuple([base64.b64decode(x)
                                          for x in bincrypt.split('!')])
                        newelement[attribute]['cryptvalue'] = bincrypt
                    elif attribute in ('nodes', '_expressionkeys'):
                        # A group with nodes
                        # delete it and defer until nodes are being added
                        # which will implicitly fill this up
                        # Or _expressionkeys attribute, which will similarly
                        # be rebuilt
                        del newelement[attribute]
                tmpconfig[confarea][element] = newelement
        # We made it through above section without an exception, go ahead and
        # replace
        # Start by erasing the dbm files if present
        for confarea in _config_areas:
            try:
                os.unlink(os.path.join(self._cfgdir, confarea))
            except OSError as e:
                if e.errno == 2:
                    pass
        # Now we have to iterate through each fixed up element, using the
        # set attribute to flesh out inheritence and expressions
        _cfgstore['main']['idmap'] = {}
        for confarea in _config_areas:
            self._cfgstore[confarea] = {}
            if confarea not in tmpconfig:
                continue
            if confarea == 'nodes':
                self.set_node_attributes(tmpconfig[confarea], True)
            elif confarea == 'nodegroups':
                self.set_group_attributes(tmpconfig[confarea], True)
            elif confarea == 'users':
                for user in tmpconfig[confarea]:
                    uid = tmpconfig[confarea].get('id', None)
                    displayname = tmpconfig[confarea].get('displayname', None)
                    self.create_user(user, uid=uid, displayname=displayname)
                    if 'cryptpass' in tmpconfig[confarea][user]:
                        self._cfgstore['users'][user]['cryptpass'] = \
                            tmpconfig[confarea][user]['cryptpass']
                        _mark_dirtykey('users', user, self.tenant)
        self._bg_sync_to_file()

    def _dump_to_json(self, redact=None):
        """Dump the configuration in json form to output

        password is used to protect the 'secret' attributes in liue of the
        actual in-configuration master key (which will have no clear form
        in the dump

        :param redact: If True, then sensitive password data will be redacted.
                       Other values may be used one day to redact in more
                       complex and interesting ways for non-secret
                       data.

        """
        dumpdata = {}
        for confarea in _config_areas:
            if confarea not in self._cfgstore:
                continue
            dumpdata[confarea] = {}
            for element in self._cfgstore[confarea]:
                dumpdata[confarea][element] = \
                    copy.deepcopy(self._cfgstore[confarea][element])
                for attribute in self._cfgstore[confarea][element]:
                    if 'inheritedfrom' in dumpdata[confarea][element][attribute]:
                        del dumpdata[confarea][element][attribute]
                    elif (attribute == 'cryptpass' or
                                  'cryptvalue' in
                                  dumpdata[confarea][element][attribute]):
                        if redact is not None:
                            dumpdata[confarea][element][attribute] = '*REDACTED*'
                        else:
                            if attribute == 'cryptpass':
                                target = dumpdata[confarea][element][attribute]
                            else:
                                target = dumpdata[confarea][element][attribute]['cryptvalue']
                            cryptval = []
                            for value in target:
                                cryptval.append(base64.b64encode(value))
                            if attribute == 'cryptpass':
                                dumpdata[confarea][element][attribute] = '!'.join(cryptval)
                            else:
                                dumpdata[confarea][element][attribute]['cryptvalue'] = '!'.join(cryptval)
                    elif isinstance(dumpdata[confarea][element][attribute], set):
                        dumpdata[confarea][element][attribute] = \
                            list(dumpdata[confarea][element][attribute])
        return json.dumps(
            dumpdata, sort_keys=True, indent=4, separators=(',', ': '))



    @classmethod
    def _read_from_path(cls):
        global _cfgstore
        _cfgstore = {}
        rootpath = cls._cfgdir
        _load_dict_from_dbm(['collective'], os.path.join(rootpath,
                                                         "collective"))
        _load_dict_from_dbm(['globals'], os.path.join(rootpath, "globals"))
        for confarea in _config_areas:
            _load_dict_from_dbm(['main', confarea], os.path.join(rootpath, confarea))
        try:
            for tenant in os.listdir(os.path.join(rootpath, 'tenants')):
                for confarea in _config_areas:
                    _load_dict_from_dbm(
                        ['main', tenant, confarea],
                        os.path.join(rootpath, tenant, confarea))
        except OSError:
            pass

    @classmethod
    def wait_for_sync(cls):
        cls._bg_sync_to_file()
        if cls._cfgwriter is not None:
            cls._cfgwriter.join()

    @classmethod
    def shutdown(cls):
        cls.wait_for_sync()
        sys.exit(0)

    @classmethod
    def _bg_sync_to_file(cls):
        if statelessmode:
            return
        with cls._syncstate:
            if cls._syncrunning:
                cls._writepending = True
                return
            cls._syncrunning = True
        # if the thread is exiting, join it to let it close, just in case
        if cls._cfgwriter is not None:
            cls._cfgwriter.join()
        cls._cfgwriter = threading.Thread(target=cls._sync_to_file)
        cls._cfgwriter.start()

    @classmethod
    def _sync_to_file(cls):
        if statelessmode:
            return
        if 'dirtyglobals' in _cfgstore:
            with _dirtylock:
                dirtyglobals = copy.deepcopy(_cfgstore['dirtyglobals'])
                del _cfgstore['dirtyglobals']
            _mkpath(cls._cfgdir)
            globalf = dbm.open(os.path.join(cls._cfgdir, "globals"), 'c', 384)  # 0600
            try:
                for globalkey in dirtyglobals:
                    if globalkey in _cfgstore['globals']:
                        globalf[globalkey] = \
                            cPickle.dumps(_cfgstore['globals'][globalkey])
                    else:
                        if globalkey in globalf:
                            del globalf[globalkey]
            finally:
                globalf.close()
        if 'collectivedirty' in _cfgstore:
            collectivef = dbm.open(os.path.join(cls._cfgdir, "collective"),
                                   'c', 384)
            try:
                with _dirtylock:
                    colls = copy.deepcopy(_cfgstore['collectivedirty'])
                    del _cfgstore['collectivedirty']
                for coll in colls:
                    if coll in _cfgstore['collective']:
                        collectivef[coll] = cPickle.dumps(
                            _cfgstore['collective'][coll])
                    else:
                        if coll in collectivef:
                            del globalf[coll]
            finally:
                collectivef.close()
        if 'dirtykeys' in _cfgstore:
            with _dirtylock:
                currdirt = copy.deepcopy(_cfgstore['dirtykeys'])
                del _cfgstore['dirtykeys']
            for tenant in currdirt:
                dkdict = currdirt[tenant]
                if tenant is None:
                    pathname = cls._cfgdir
                    currdict = _cfgstore['main']
                else:
                    pathname = os.path.join(cls._cfgdir, 'tenants', tenant)
                    currdict = _cfgstore['tenant'][tenant]
                for category in dkdict:
                    _mkpath(pathname)
                    dbf = dbm.open(os.path.join(pathname, category), 'c', 384)  # 0600
                    try:
                        for ck in dkdict[category]:
                            if ck not in currdict[category]:
                                if ck in dbf:
                                    del dbf[ck]
                            else:
                                dbf[ck] = cPickle.dumps(currdict[category][ck])
                    finally:
                        dbf.close()
        willrun = False
        with cls._syncstate:
            if cls._writepending:
                cls._writepending = False
                willrun = True
            else:
                cls._syncrunning = False
        if willrun:
            return cls._sync_to_file()

    def _recalculate_expressions(self, cfgobj, formatter, node, changeset):
        for key in cfgobj:
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


def _restore_keys(jsond, password, newpassword=None):
    # the jsond from the restored file, password (if any) used to protect
    # the file, and newpassword to use, (also check the service.cfg file)
    global _masterkey
    global _masterintegritykey
    keydata = json.loads(jsond)
    cryptkey = _parse_key(keydata['cryptkey'], password)
    integritykey = _parse_key(keydata['integritykey'], password)
    conf.init_config()
    cfg = conf.get_config()
    if cfg.has_option('security', 'externalcfgkey'):
        keyfilename = cfg.get('security', 'externalcfgkey')
        with open(keyfilename, 'r') as keyfile:
            newpassword = keyfile.read()
    set_global('master_privacy_key', _format_key(cryptkey,
                                                 password=newpassword))
    set_global('master_integrity_key', _format_key(integritykey,
                                                   password=newpassword))
    _masterkey = cryptkey
    _masterintegritykey = integritykey
    ConfigManager.wait_for_sync()
    # At this point, we should have the key situation all sorted


def _dump_keys(password, dojson=True):
    if _masterkey is None or _masterintegritykey is None:
        init_masterkey()
    cryptkey = _format_key(_masterkey, password=password)
    if 'passphraseprotected' in cryptkey:
        cryptkey = '!'.join(map(base64.b64encode,
                                cryptkey['passphraseprotected']))
    else:
        cryptkey = '*unencrypted:{0}'.format(base64.b64encode(
            cryptkey['unencryptedvalue']))
    integritykey = _format_key(_masterintegritykey, password=password)
    if 'passphraseprotected' in integritykey:
        integritykey = '!'.join(map(base64.b64encode,
                                    integritykey['passphraseprotected']))
    else:
        integritykey = '*unencrypted:{0}'.format(base64.b64encode(
            integritykey['unencryptedvalue']))
    keydata = {'cryptkey': cryptkey, 'integritykey': integritykey}
    if dojson:
        return json.dumps(keydata, sort_keys=True, indent=4, separators=(',', ': '))
    return keydata


def restore_db_from_directory(location, password):
    try:
        with open(os.path.join(location, 'keys.json'), 'r') as cfgfile:
            keydata = cfgfile.read()
            json.loads(keydata)
            _restore_keys(keydata, password)
    except IOError as e:
        if e.errno == 2:
            raise Exception("Cannot restore without keys, this may be a "
                            "redacted dump")
    try:
        moreglobals = json.load(open(os.path.join(location, 'globals.json')))
        for globvar in moreglobals:
            set_global(globvar, moreglobals[globvar])
    except IOError as e:
        if e.errno != 2:
            raise
    try:
        collective = json.load(open(os.path.join(location, 'collective.json')))
        for coll in collective:
            add_collective_member(coll, collective[coll]['address'],
                                  collective[coll]['fingerprint'])
    except IOError as e:
        if e.errno != 2:
            raise
    with open(os.path.join(location, 'main.json'), 'r') as cfgfile:
        cfgdata = cfgfile.read()
        ConfigManager(tenant=None)._load_from_json(cfgdata)


def dump_db_to_directory(location, password, redact=None, skipkeys=False):
    if not redact and not skipkeys:
        with open(os.path.join(location, 'keys.json'), 'w') as cfgfile:
            cfgfile.write(_dump_keys(password))
            cfgfile.write('\n')
    if 'collective' in _cfgstore:
        with open(os.path.join(location, 'collective.json'), 'w') as cfgfile:
            cfgfile.write(json.dumps(_cfgstore['collective']))
            cfgfile.write('\n')
    with open(os.path.join(location, 'main.json'), 'w') as cfgfile:
        cfgfile.write(ConfigManager(tenant=None)._dump_to_json(redact=redact))
        cfgfile.write('\n')
    bkupglobals = get_globals()
    if bkupglobals:
        json.dump(bkupglobals, open(os.path.join(location, 'globals.json'),
                                    'w'))
    try:
        for tenant in os.listdir(
                os.path.join(ConfigManager._cfgdir, '/tenants/')):
            with open(os.path.join(location, 'tenants', tenant,
                                   'main.json'), 'w') as cfgfile:
                cfgfile.write(ConfigManager(tenant=tenant)._dump_to_json(
                    redact=redact))
                cfgfile.write('\n')
    except OSError:
        pass


def get_globals():
    bkupglobals = {}
    for globvar in _cfgstore['globals']:
        if globvar.endswith('_key'):
            continue
        bkupglobals[globvar] = _cfgstore['globals'][globvar]
    return bkupglobals


def init(stateless=False):
    global _cfgstore
    if stateless:
        _cfgstore = {}
        return
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
