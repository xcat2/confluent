# authentication and authorization routines for confluent

import confluent.config as config

def authorize(name, element):
    #TODO: actually use the element to ascertain if this user is good enough
    try:
        if '/' in name:
            tenant, user = name.split('/', 1)
            tenant = config.get_tenant_id(tenant)
            user = config.get_user(user, tenant)
        elif name in config.get_tenant_names():
            tenant = config.get_tenant_id(name)
            user = config.get_user(name, tenant)
        else:
            user = config.get_user(name, 0)
            tenant = 0
        return (tenant, user)
    except:
        print "uh oh"
        return None



