# authentication and authorization routines for confluent
# authentication scheme caches passphrase values to help HTTP Basic auth
# the PBKDF2 transform is skipped unless a user has been idle for sufficient 
# time

import confluent.config as config
import eventlet
import Crypto.Protocol.KDF as kdf
import Crypto.Hash as hash
import os
import time

_passcache = {}
_passchecking = {}


def _prune_passcache():
    # This function makes sure we don't remember a passphrase in memory more
    # than 10 seconds
    while (1):
        curtime = time.time()
        for passent in _passcache.iterkeys():
            if passent[2] < curtime - 10:
                del _passcache[passent]
        eventlet.sleep(10)


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
    if not isinstance(tenant,bool):
        # if not boolean, it must be explicit tenant
        user = name
    elif '/' in name:  # tenant scoped name
        tenant, user = name.split('/', 1)
    elif config.is_tenant(name):
        # the account is the implicit tenant owner account
        user = name
        tenant = name
    else: # assume it is a non-tenant user account
        user = name
        tenant = None
    yield user
    yield tenant

def authorize(name, element, tenant=False, access='rw'):
    #TODO: actually use the element to ascertain if this user is good enough
    """Determine whether the given authenticated name is authorized.

    :param name: The shortname authenticated by the authentication scheme
    :param element: The path being examined.
    :param tenant: The tenant under which the account exists (defaults to
                    detect from name)
    :param access: Defaults to 'rw', can check 'ro' access

    returns None if authorization fails or a tuple of the user object
            and the relevant ConfigManager object for the context of the
            request.
    """
    user, tenant = _get_usertenant(name, tenant)
    if tenant is not None and not config.is_tenant(tenant):
        return None
    configmanager = config.ConfigManager(tenant)
    userobj = configmanager.get_user(user)
    if userobj: #returning
        return (userobj, configmanager)
    return None


def set_user_passphrase(name, passphrase, tenant=None):
    """Set user passphrase

    :param name: The unique shortname of the user
    :param passphrase: The passphrase to set for given user
    :param tenant: The tenant to which the user belongs.
    """
    # TODO(jbjohnso): WORKERPOOL
    # When worker pool implemented, hand off the
    # PBKDF2 to a worker instead of blocking
    user, tenant = _get_usertenant(name, tenant)
    _passcache[(user, tenant)] = passphrase
    salt = os.urandom(8)
    crypted = kdf.PBKDF2(passphrase, salt, 32, 10000,
                lambda p, s: hash.HMAC.new(p, s, hash.SHA256).digest())
    cfm = config.ConfigManager(tenant)
    cfm.set_user(name, { 'cryptpass': (salt, crypted) })


def check_user_passphrase(name, passphrase, element=None, tenant=False):
    """Check a a login name and passphrase for authenticity and authorization

    The function combines authentication and authorization into one function.
    It is highly recommended for a session layer to provide some secure means
    of protecting a session once this function works once and calling
    authorize() in order to provide best performance regardless of
    circumstance.  The function makes effort to provide good performance
    in repeated invocation, but that facility will slow down to deter
    detected passphrase guessing activity when such activity is detected.

    :param name: The login name provided by client
    :param passhprase: The passphrase provided by client
    :param element: Optional specification of a particular destination
    :param tenant: Optional explicit indication of tenant (defaults to
                   embedded in name)
    """
    # If there is any sign of guessing on a user, all valid and
    # invalid attempts are equally slowed to no more than 20 per second
    # for that particular user.
    # similarly, guessing usernames is throttled to 20/sec
    user, tenant = _get_usertenant(name, tenant)
    while (user,tenant) in _passchecking:
        # Want to serialize passphrase checking activity
        # by a user, which might be malicious
        # would normally make an event and wait
        # but here there's no need for that
        eventlet.sleep(0.5)
    if (user,tenant) in _passcache:
        if passphrase == _passcache[(user,tenant)]:
            return authorize(user, element, tenant)
        else:
            # In case of someone trying to guess,
            # while someone is legitimately logged in
            # invalidate cache and force the slower check
            del _passcache[(user, tenant)]
            return None
    cfm = config.ConfigManager(tenant)
    ucfg = cfm.get_user(user)
    if ucfg is None or 'cryptpass' not in ucfg:
        eventlet.sleep(0.05) #stall even on test for existance of a username
        return None
    _passchecking[(user, tenant)] = True
    # TODO(jbjohnso): WORKERPOOL
    # PBKDF2 is, by design, cpu intensive
    # throw it at the worker pool when implemented
    salt, crypt = ucfg['cryptpass']
    crypted = kdf.PBKDF2(passphrase, salt, 32, 10000,
                lambda p, s: hash.HMAC.new(p, s, hash.SHA256).digest())
    del _passchecking[(user, tenant)]
    eventlet.sleep(0.05) #either way, we want to stall so that client can't
        # determine failure because there is a delay, valid response will
        # delay as well
    if crypt == crypted:
        _passcache[(user, tenant)] = passphrase
        return authorize(user, element, tenant)
    return None
