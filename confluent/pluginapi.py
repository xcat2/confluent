# concept here that mapping from the resource tree and arguments go to
# specific python class signatures.  The intent is to require
# plugin authors to come here if they *really* think they need new 'commands'
# and hopefully curtail deviation by each plugin author

# have to specify a standard place for cfg selection of *which* plugin
# as well a standard to map api requests to python funcitons
# e.g. <nodeelement>/power/state maps to some plugin HardwareManager.get_power/set_power
# selected by hardwaremanagement.method
# plugins can advertise a set of names if there is a desire for readable things
# exceptions to handle os images
# endpoints point to a class... usually, the class should have:
# -create
# -retrieve
# -update
# -delete
# functions.  Console is special and just get's passed through
# see API.txt

import confluent.interface.console as console
import os
import sys

pluginmap = {}


def load_plugins():
    # To know our plugins directory, we get the parent path of 'bin'
    path=os.path.dirname(os.path.realpath(__file__))
    plugindir = os.path.realpath(os.path.join(path,'..','plugins'))
    sys.path.append(plugindir)
    plugins = set()
    #two passes, to avoid adding both py and pyc files
    for plugin in os.listdir(plugindir):
        plugin = os.path.splitext(plugin)[0]
        plugins.add(plugin)
    for plugin in plugins:
        if plugin.startswith('.'):
            continue
        tmpmod = __import__(plugin)
        if 'plugin_names' in tmpmod.__dict__:
            for name in tmpmod.plugin_names:
                pluginmap[name] = tmpmod
        else:
            pluginmap[plugin] = tmpmod

nodetree = {
    '/': ['power/', 'boot/', 'console/', 'attributes/'],
    '/power/': ['state'],
    '/boot/': ['device'],
    '/console/': ['session', 'logging'],
}

# _ elements are for internal use (e.g. special console scheme)
nodeelements = {
    '_console/session': {
        'pluginattrs': ['console.method' ,'hardwaremanagement.method'],
    },
    'console/session': {
        'pluginattrs': ['console.method' ,'hardwaremanagement.method'],
    },
    'power/state': {
        'pluginattrs': ['hardwaremanagement.method'],
        'default': 'ipmi',
    },
    'boot/device': {
        'pluginattrs': ['hardwaremanagement.method'],
        'default': 'ipmi',
    }
}

def stripnode(iterablersp, node):
    for i in iterablersp:
        i.strip_node(node)
        yield i

def handle_path(path, operation, configmanager):
    '''Given a full path request, return an object.

    The plugins should generally return some sort of iterator.
    An exception is made for console/session, which should return
    a class with connect(), read(), write(bytes), and close()
    '''
    if (path.startswith("/node/") or path.startswith("/system/") or
        # single node requests
            path.startswith("/vm/")):
        nodeidx = path.find("/",1) + 1
        node = path[nodeidx:]
        node, _, element = node.partition("/")
        if element not in nodeelements:
            raise Exception("Invalid element requested")
        plugroute = nodeelements[element]
        if 'pluginattrs' in plugroute:
            nodeattr = configmanager.get_node_attributes(
                [node], plugroute['pluginattrs'])
            for attrname in plugroute['pluginattrs']:
                if attrname in nodeattr[node]:
                    passvalue = pluginmap[nodeattr[node][attrname]['value']].__dict__[operation](
                        nodes=(node,), element=element,
                        configmanager=configmanager)
            if 'default' in plugroute:
                passvalue = pluginmap[plugroute['default']].__dict__[operation](
                    nodes=(node,), element=element, configmanager=configmanager)
        if isinstance(passvalue, console.Console):
            return passvalue
        else:
            return stripnode(passvalue)
    else:
        raise Exception("TODO: notfoundexception")



