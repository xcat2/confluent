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

# authentication and authorization routines for confluent
# authentication scheme caches passphrase values to help HTTP Basic auth
# the PBKDF2 transform is skipped unless a user has been idle for sufficient
# time

import confluent.config.configmanager as configmanager
import eventlet
import eventlet.tpool
try:
    import Cryptodome.Protocol.KDF as KDF
except ImportError:
    import Crypto.Protocol.KDF as KDF
from fnmatch import fnmatch
import hashlib
import hmac
import msgpack
import multiprocessing
import os
import pwd
import confluent.userutil as userutil
import confluent.util as util
pam = None
try:
    import confluent.pam as pam
except ImportError:
    pass
import time
import yaml

_pamservice = 'confluent'
_passcache = {}
_passchecking = {}

authworkers = None
authcleaner = None

_allowedbyrole = {
    'Operator': {
        'retrieve': ['*'],
        'create': [
            '/noderange/',
            '/nodes/',
            '/node*/media/uploads/',
            '/node*/inventory/firmware/updates/*',
            '/node*/suppport/servicedata*',
            '/node*/attributes/expression',
            '/nodes/*/console/session*',
            '/nodes/*/shell/sessions*',
            '/node*/configuration/*',
        ],
        'update': [
            '/discovery/*',
            '/networking/macs/rescan',
            '/node*/power/state',
            '/node*/power/reseat',
            '/node*/attributes/*',
            '/node*/media/*tach',
            '/node*/boot/nextdevice',
            '/node*/identify',
            '/node*/configuration/*',
        ],
        'start': [
            '/sessions/current/async',
            '/nodes/*/console/session*',
            '/nodes/*/shell/sessions*',
        ],
        'delete': [
            '/discovery/*',
            '/node*',
        ],
    },
    'Monitor': {
        'start': [
            '/sessions/current/async',
        ],
        'retrieve': [
            '/node*/health/hardware',
            '/node*/power/state',
            '/node*/sensors/*',
            '/node*/attributes/current',
            '/node*/description',
            '/noderange/*/nodes/',
            '/nodes/',
            '/',
        ],
    }
}

_deniedbyrole = {
    # This supersedes the above and is only consulted after the allowed has happened
    'Operator': {
        'update': [
            '/node*/configuration/management_controller/users/*',
        ]
    }
}


class PromptsNeeded(Exception):
    def __init__(self, prompts):
        self.prompts = prompts

#add function to change _allowedbyrole and _deniedbyrole vars.
def add_roles(_allowed,_denied):
    # function to parse the roles and the files. If there are modifications to be done to the roles, items will be added to dictionaries.
    # If there are no moodifications done to one of the roles, it continues to the next
    # Opening YAML file and reading the custom roles
    with open("/etc/confluent/authorization.yaml","r") as stream:
        loaded_file = yaml.safe_load(stream)
        try:
            allowed_loaded = loaded_file["allowedbyrole"]
            for role in allowed_loaded:
                if role not in configmanager._validroles:
                    configmanager._validroles.append(role)
        except:
            pass
        try:
            denied_loaded = loaded_file["deniedbyrole"]
        except:
            pass
 
        try:
            _allowed.update(allowed_loaded)
        except NameError:
            pass
        try: 
            _denied.update(denied_loaded)
        except NameError:
            pass
        return
                
    
def check_for_yaml():
    #checking if the file exists
    if os.path.exists("/etc/confluent/authorization.yaml"):
        add_roles(_allowedbyrole,_deniedbyrole)

        return "Custom auth. file detected in /etc/confluent, updated roles accordingly"
    else:
        return "No custom auth. file. Continuing as normal"
    

        
def _get_usertenant(name, tenant=False):
    """_get_usertenant

    Convenience function to parse name into username and tenant.
    If tenant is explicitly passed in, then name must be the username
    tenant name with '/' is forbidden.  If '/' is seen in name, tenant
    is assumed to preface the /.
    If the username is a tenant name, then it is to be the implied
    administrator account a tenant gets.
    Otherwise, just assume a user in the default tenant
    """
    if not isinstance(name, bytes):
        name = name.encode('utf-8')
    if not isinstance(tenant, bool):
        # if not boolean, it must be explicit tenant
        user = name
    elif b'/' in name:  # tenant scoped name
        tenant, user = name.split(b'/', 1)
    elif configmanager.is_tenant(name):
        # the account is the implicit tenant owner account
        user = name
        tenant = name
    else:  # assume it is a non-tenant user account
        user = name
        tenant = None
    user = util.stringify(user)
    if tenant:
        tenant = util.stringify(tenant)
    yield user
    yield tenant


def authorize(name, element, tenant=False, operation='create',
              skipuserobj=False):
    #TODO: actually use the element to ascertain if this user is good enough
    """Determine whether the given authenticated name is authorized.

    :param name: The shortname authenticated by the authentication scheme
    :param element: The path being examined.
    :param tenant: The tenant under which the account exists (defaults to
                    detect from name)
    :param operation: Defaults to checking for 'create' level access

    returns None if authorization fails or a tuple of the user object
            and the relevant ConfigManager object for the context of the
            request.
    """
    # skipuserobj is a leftover from the now abandoned plan to use pam session
    # to do authorization and authentication.  Now confluent always does authorization
    # even if pam does authentication.
    if operation not in ('create', 'start', 'update', 'retrieve', 'delete', None):
        return False
    user, tenant = _get_usertenant(name, tenant)
    if tenant is not None and not configmanager.is_tenant(tenant):
        return False
    manager = configmanager.ConfigManager(tenant, username=user)
    userobj = manager.get_user(user)
    if element and (element.startswith('/sessions/current/webauthn/registered_credentials/') or  element.startswith('/sessions/current/webauthn/validate/')):
        return userobj, manager, user, tenant, skipuserobj
    if userobj and userobj.get('role', None) == 'Stub':
        userobj = None
    if not userobj:
        for group in userutil.grouplist(user):
            userobj = manager.get_usergroup(group)
            if userobj:
                break
    if userobj:  # returning
        role = userobj.get('role', 'Administrator')
        if element and role != 'Administrator':
            for rule in _allowedbyrole.get(role, {}).get(operation, []):
                if fnmatch(element, rule):
                    break
            else:
                return False
            for rule in _deniedbyrole.get(role, {}).get(operation, []):
                if fnmatch(element, rule):
                    return False
        return userobj, manager, user, tenant, skipuserobj
    return False


def check_user_passphrase(name, passphrase, operation=None, element=None, tenant=False):
    """Check a a login name and passphrase for authenticity and authorization

    The function combines authentication and authorization into one function.
    It is highly recommended for a session layer to provide some secure means
    of protecting a session once this function works once and calling
    authorize() in order to provide best performance regardless of
    circumstance.  The function makes effort to provide good performance
    in repeated invocation, but that facility will slow down to deter
    detected passphrase guessing activity when such activity is detected.

    :param name: The login name provided by client
    :param passphrase: The passphrase provided by client
    :param element: Optional specification of a particular destination
    :param tenant: Optional explicit indication of tenant (defaults to
                   embedded in name)
    """
    # The reason why tenant is 'False' instead of 'None':
    # None means explicitly not a tenant.  False means check
    # the username for signs of being a tenant
    # If there is any sign of guessing on a user, all valid and
    # invalid attempts are equally slowed to no more than 20 per second
    # for that particular user.
    # similarly, guessing usernames is throttled to 20/sec
    user, tenant = _get_usertenant(name, tenant)
    while (user, tenant) in _passchecking:
        # Want to serialize passphrase checking activity
        # by a user, which might be malicious
        # would normally make an event and wait
        # but here there's no need for that
        eventlet.sleep(0.5)
    cfm = configmanager.ConfigManager(tenant, username=user)
    ucfg = cfm.get_user(user)
    if ucfg is None:
        try:
            for group in userutil.grouplist(user):
                ucfg = cfm.get_usergroup(group)
                if ucfg:
                    break
        except KeyError:
            pass
    if ucfg is None:
        eventlet.sleep(0.05)
        return None
    bpassphrase = None
    if isinstance(passphrase, dict) and len(passphrase) == 1:
        passphrase = list(passphrase.values())[0]
    if isinstance(passphrase, bytes):
        bpassphrase = passphrase
    elif not isinstance(passphrase, dict):
        bpassphrase = passphrase.encode('utf8')
    if (user, tenant) in _passcache and bpassphrase:
        if hashlib.sha256(bpassphrase).digest() == _passcache[(user, tenant)]:
            return authorize(user, element, tenant, operation=operation)
        else:
            # In case of someone trying to guess,
            # while someone is legitimately logged in
            # invalidate cache and force the slower check
            del _passcache[(user, tenant)]
    if 'cryptpass' in ucfg and bpassphrase:
        _passchecking[(user, tenant)] = True
        # TODO(jbjohnso): WORKERPOOL
        # PBKDF2 is, by design, cpu intensive
        # throw it at the worker pool when implemented
        # maybe a distinct worker pool, wondering about starving out non-auth stuff
        salt, crypt = ucfg['cryptpass']
        # execute inside tpool to get greenthreads to give it a special thread
        # world
        # TODO(jbjohnso): util function to generically offload a call
        # such a beast could be passed into pyghmi as a way for pyghmi to
        # magically get offload of the crypto functions without having
        # to explicitly get into the eventlet tpool game
        global authworkers
        global authcleaner
        if authworkers is None:
            authworkers = multiprocessing.Pool(processes=1)
        else:
            authcleaner.cancel()
        authcleaner = eventlet.spawn_after(30, _clean_authworkers)
        crypted = eventlet.tpool.execute(_do_pbkdf, passphrase, salt)
        del _passchecking[(user, tenant)]
        eventlet.sleep(
            0.05)  # either way, we want to stall so that client can't
        # determine failure because there is a delay, valid response will
        # delay as well
        if crypt == crypted:
            _passcache[(user, tenant)] = hashlib.sha256(bpassphrase).digest()
            return authorize(user, element, tenant, operation)
    if pam:
        pwe = None
        try:
            pwe = pwd.getpwnam(user)
        except KeyError:
            #pam won't work if the user doesn't exist, don't go further
            eventlet.sleep(0.05)  # stall even on test for existence of a username
            return None
        if os.getuid() != 0:
            # confluent is running with reduced privilege, however, pam_unix refuses
            # to let a non-0 user check anothers password.
            # We will fork and the child will assume elevated privilege to
            # get unix_chkpwd helper to enable checking /etc/shadow
            getprompt, sendprompt = os.pipe()
            getprompt, sendprompt = os.fdopen(getprompt, 'rb', 0), os.fdopen(sendprompt, 'wb', 0)
            pid = os.fork()
            if not pid:
                usergood = False
                try:
                    getprompt.close()
                    # we change to the uid we are trying to authenticate as, because
                    # pam_unix uses unix_chkpwd which reque
                    os.setuid(pwe.pw_uid)
                    pa = pam.pam()
                    usergood = pa.authenticate(user, passphrase, service=_pamservice)
                    if (not usergood and len(pa.prompts) > 1 and
                            (not isinstance(passphrase, dict) or
                            (set(passphrase) - pa.prompts))):
                        sendprompt.write(msgpack.packb(list(pa.prompts)))
                        sendprompt.close()
                        os._exit(2)
                finally:
                    os._exit(0 if usergood else 1)
            sendprompt.close()
            usergood = os.waitpid(pid, 0)[1]
            if (usergood >> 8) == 2:
                prompts = getprompt.read()
                if (prompts):
                    raise PromptsNeeded(msgpack.unpackb(prompts))
            usergood = usergood == 0
            getprompt.close()
        else:
            # We are running as root, we don't need to fork in order to authenticate the
            # user
            usergood = pam.authenticate(user, passphrase, service=_pamservice)
        if usergood:
            if bpassphrase:
                _passcache[(user, tenant)] = hashlib.sha256(bpassphrase).digest()
            return authorize(user, element, tenant, operation, skipuserobj=False)
    eventlet.sleep(0.05)  # stall even on test for existence of a username
    return None

def _apply_pbkdf(passphrase, salt):
    return KDF.PBKDF2(passphrase, salt, 32, 10000,
                      lambda p, s: hmac.new(p, s, hashlib.sha256).digest())


def _clean_authworkers():
    global authworkers
    global authcleaner
    authworkers = None
    authcleaner = None


def _do_pbkdf(passphrase, salt):
    # we must get it over to the authworkers pool or else get blocked in
    # compute.  However, we do want to wait for result, so we have
    # one of the exceedingly rare sort of circumstances where 'apply'
    # actually makes sense
    return authworkers.apply(_apply_pbkdf, [passphrase, salt])
