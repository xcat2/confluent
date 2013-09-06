# authentication and authorization routines for confluent

import confluent.config as config

def authorize(name, element, tenant=None, access='rw'):
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
    if tenant is not None:
        user = name
    elif '/' in name:
        tenant, user = name.split('/', 1)
    elif config.is_tenant(name):
        user = name
        tenant = name
    else:
        user = name
        tenant = 0
    if not config.is_tenant(tenant):
        return None
    configmanager = config.ConfigManager(tenant)
    userobj = configmanager.get_user(user)
    if userobj: #returning
        return (userobj, configmanager)
    return None
