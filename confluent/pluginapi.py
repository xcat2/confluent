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
import confluent.exceptions as exc
import confluent.messages as msg
import os
import sys

pluginmap = {}

def nested_lookup(nestdict, key):
    return reduce(dict.__getitem__, key, nestdict)

def load_plugins():
    # To know our plugins directory, we get the parent path of 'bin'
    path=os.path.dirname(os.path.realpath(__file__))
    plugintop = os.path.realpath(os.path.join(path,'..','plugins'))
    plugins = set()
    for plugindir in os.listdir(plugintop):
        plugindir = os.path.join(plugintop,plugindir)
        if not os.path.isdir(plugindir):
            continue
        sys.path.append(plugindir)
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


nodecollections = {
    'power/': ['state'],
    'boot/': ['device'],
    'console/': ['session', 'logging'],
    'attributes/': [],  # TODO: put in the 'categories' automaticly from
                            # confluent.config.attributes
}

rootcollections = {
    'node/': nodecollections
}

class PluginRoute(object):
    def __init__(self, routedict):
        self.routeinfo = routedict
# _ prefix indicates internal use (e.g. special console scheme) and should not
# be enumerated in any collection
noderesources = {
    '_console': {
        'session': PluginRoute({
            'pluginattrs': ['console.method' ,'hardwaremanagement.method'],
        }),
    },
    'console': {
        #this is a dummy value, http or socket must handle special
        'session': PluginRoute({}),
    },
    'power': {
        'state': PluginRoute({
            'pluginattrs': ['hardwaremanagement.method'],
            'default': 'ipmi',
        }),
    },
    'boot': {
        'device': PluginRoute({
            'pluginattrs': ['hardwaremanagement.method'],
            'default': 'ipmi',
        }),
    },
    'attributes': {
        'all': PluginRoute({ 'handler': 'attributes' }),
        'current': PluginRoute({ 'handler': 'attributes' }),
    },
}

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
    },
    'attributes/all': {
        'handler': 'attributes',
    },
    'attributes/current': {
        'handler': 'attributes',
    },
}

def stripnode(iterablersp, node):
    for i in iterablersp:
        i.strip_node(node)
        yield i

def iterate_collections(iterable):
    for coll in iterable:
        if coll[-1] != '/':
            coll = coll + '/'
        yield msg.ChildCollection(coll)

def iterate_resources(fancydict):
    for resource in fancydict.iterkeys():
        if resource.startswith("_"):
            continue
        if not isinstance(fancydict[resource], PluginRoute):  # a resource
            resource += '/'
        yield msg.ChildCollection(resource)

def enumerate_node_collection(collectionpath, configmanager):
    print repr(collectionpath)
    if collectionpath == [ 'node' ]:  #it is simple '/node/', need a list of nodes
        return iterate_collections(configmanager.get_nodes())
    del collectionpath[0:2]
    collection = nested_lookup(noderesources, collectionpath)
    return iterate_resources(collection)


def enumerate_collections(collections):
    for collection in collections.iterkeys():
        yield msg.ChildCollection(collection)

def handle_path(path, operation, configmanager, inputdata=None):
    '''Given a full path request, return an object.

    The plugins should generally return some sort of iterator.
    An exception is made for console/session, which should return
    a class with connect(), read(), write(bytes), and close()
    '''
    iscollection = False
    pathcomponents = path.split('/')
    del pathcomponents[0]  # discard the value from leading /
    print repr(pathcomponents)
    if pathcomponents[-1] == '':
        iscollection = True
        del pathcomponents[-1]
    if not pathcomponents: #root collection list
        return enumerate_collections(rootcollections)
    elif pathcomponents[0] in ('node', 'system', 'vm'):
        #single node request of some sort
        try:
            node = pathcomponents[1]
        except IndexError:  # doesn't actually have a long enough path
            return iterate_collections(configmanager.get_nodes())
        if iscollection:
            return enumerate_node_collection(pathcomponents, configmanager)
        print repr(pathcomponents)
        del pathcomponents[0:2]
        print repr(pathcomponents)
        try:
            plugroute = nested_lookup(noderesources, pathcomponents).routeinfo
        except KeyError:
            raise exc.NotFoundException("Invalid element requested")
        inputdata = msg.get_input_message(pathcomponents, operation, inputdata, (node,))
        if 'handler' in plugroute:  #fixed handler definition
            passvalue = pluginmap[plugroute['handler']].__dict__[operation](
                nodes=(node,), element=pathcomponents,
                configmanager=configmanager,
                inputdata=inputdata)
        elif 'pluginattrs' in plugroute:
            nodeattr = configmanager.get_node_attributes(
                [node], plugroute['pluginattrs'])
            for attrname in plugroute['pluginattrs']:
                if attrname in nodeattr[node]:
                    passvalue = pluginmap[nodeattr[node][attrname]['value']].__dict__[operation](
                        nodes=(node,), element=pathcomponents,
                        configmanager=configmanager,
                        inputdata=inputdata)
            if 'default' in plugroute:
                passvalue = pluginmap[plugroute['default']].__dict__[operation](
                    nodes=(node,), element=pathcomponents, configmanager=configmanager,
                    inputdata=inputdata)
        if isinstance(passvalue, console.Console):
            return passvalue
        else:
            return stripnode(passvalue, node)
    else:
        raise exc.NotFoundException()



