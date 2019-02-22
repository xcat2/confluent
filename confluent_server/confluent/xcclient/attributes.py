###############################################################################
# IBM(c) 2019 EPL license http://www.eclipse.org/legal/epl-v10.html
###############################################################################
# -*- encoding: utf-8 -*-


# 'node', which can be considered a 'system' or a 'vm'
nodeattrs = {
    'groups': 'nodelist.groups',
    'collective.manager': 'nodehm.mgt',
    'discovery.passwordrules': None,
    'discovery.policy': ['switch', 'mtms', 'sequential'],
    'info.note': 'nodelist.comments',
    'location.room': 'nodepos.room',
    'location.row': 'nodepos.comments', 
    'location.rack': 'nodepos.rack',
    'location.u': 'nodepos.u',
    'console.logging': 'site.consoleondemand',
    'console.method': 'nodehm.cons',
    'virtualization.host': 'vm.host',
    'hardwaremanagement.manager': 'ipmi.bmc',
    'hardwaremanagement.method': 'nodehm.mgt',
    'enclosure.bay': None,
    'enclosure.extends': None,
    'enclosure.manager': None,
    'id.model': 'vpd.mtm',
    'id.serial': 'vpd.serial',
    'id.uuid': 'vpd.uuid',
    'net.bootable': None, 
    'net.ipv4_gateway': None,
    'net.hwaddr': 'mac.mac',
    'net.switch': 'switch.switch',
    'net.switchport': 'switch.port',
    'secret.snmpcommunity': 'site.snmpc',
    'secret.ipmikg': None,
    'secret.hardwaremanagementuser': 'ipmi.username',
    'secret.hardwaremanagementpassword': 'ipmi.password',
    'pubkeys.addpolicy': None,
    'pubkeys.ssh': None,
}

def conattr2xcatattr(attrs=()):
    if '*' in attrs or attrs == ():
        return nodeattrs
    attr_dict = {}
    if not isinstance(attrs, list):
        attr_dict[attrs] = nodeattrs.get(attrs, None)
    else:
        for attr in attrs:
            attr_dict[attr] = nodeattrs.get(attr, None)
    return attr_dict

def conattr2xcatattrv1(attrs):
    if '*' in attrs:
        attrs = nodeattrs.keys()
    all_attr_set=set(nodeattrs.keys())
    check_set=set(attrs)
    unknown_attrs = check_set - all_attr_set
    known_attrs = check_set & all_attr_set
    if len(unknown_attrs) > 0:
        return "The attrs " + str(unknown_attrs) + " are unknown"
    tab_cols={}
    error_attrs=[]
    for attr in known_attrs:
        xcatattr = nodeattrs[attr]
        if xcatattr is None:
            print(attr + " value is None?")
            error_attrs.append(attr)
        elif isinstance(xcatattr, list):
            for k in xcatattr:
                t,p,c = k.rpartition('.')
                if t in tab_cols:
                    tab_cols[t].append(c)
                else:
                    tab_cols[t] = [c]
        else:
            t,p,c = xcatattr.rpartition('.')
            if t in tab_cols:
                tab_cols[t].append(c)
            else:
                tab_cols[t] = [c]
    if len(error_attrs):
        return "The attrs " + str(error_attrs) + " are not supported yet"
    return tab_cols
       
if __name__ == '__main__':
    #print(conattr2xcatattrv2(['hardwaremanagement.manager','collective.manager', 'secret.hardwaremanagementuser']))
    #print(conattr2xcatattr(['hardwaremanagement.manager','collective.manager', 'secret.hardwaremanagementuser']))
    #print(conattr2xcatattr())
    #mydict = conattr2xcatattr(['hardwaremanagement.manager','collective.manager', 'secret.hardwaremanagementuser'])
    mydict = conattr2xcatattr('*')
    print(get_node_attr(mydict))
    
