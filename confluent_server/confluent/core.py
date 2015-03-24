# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 IBM Corporation
# Copyright 2015 Lenovo
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
# concept here that mapping from the resource tree and arguments go to
# specific python class signatures.  The intent is to require
# plugin authors to come here if they *really* think they need new 'commands'
# and hopefully curtail deviation by each plugin author

# have to specify a standard place for cfg selection of *which* plugin
# as well a standard to map api requests to python funcitons
# e.g. <nodeelement>/power/state maps to some plugin
# HardwareManager.get_power/set_power selected by hardwaremanagement.method
# plugins can advertise a set of names if there is a desire for readable things
# exceptions to handle os images
# endpoints point to a class... usually, the class should have:
# -create
# -retrieve
# -update
# -delete
# functions.  Console is special and just get's passed through
# see API.txt

import confluent.config.attributes as attrscheme
import confluent.interface.console as console
import confluent.exceptions as exc
import confluent.messages as msg
import confluent.noderange as noderange
import confluent.shellmodule as shellmodule
import itertools
import os
import sys

pluginmap = {}

def seek_element(currplace, currkey):
    try:
        return currplace[currkey]
    except TypeError:
        if isinstance(currplace, PluginCollection):
            # we hit a plugin curated collection, all children
            # are up to the plugin to comprehend
            return currplace
        raise

def nested_lookup(nestdict, key):
    try:
        return reduce(seek_element, key, nestdict)
    except TypeError as e:
        raise exc.NotFoundException("Invalid element requested")


def load_plugins():
    # To know our plugins directory, we get the parent path of 'bin'
    path = os.path.dirname(os.path.realpath(__file__))
    plugintop = os.path.realpath(os.path.join(path, 'plugins'))
    plugins = set()
    for plugindir in os.listdir(plugintop):
        plugindir = os.path.join(plugintop, plugindir)
        if not os.path.isdir(plugindir):
            continue
        sys.path.append(plugindir)
        #two passes, to avoid adding both py and pyc files
        for plugin in os.listdir(plugindir):
            if plugin.startswith('.'):
                continue
            (plugin, plugtype) = os.path.splitext(plugin)
            if plugtype == '.sh':
                pluginmap[plugin] = shellmodule.Plugin(
                    os.path.join(plugindir, plugin + '.sh'))
            else:
                plugins.add(plugin)
        for plugin in plugins:
            tmpmod = __import__(plugin)
            if 'plugin_names' in tmpmod.__dict__:
                for name in tmpmod.plugin_names:
                    pluginmap[name] = tmpmod
            else:
                pluginmap[plugin] = tmpmod


rootcollections = ['noderange/', 'nodes/', 'nodegroups/', 'users/']


class PluginRoute(object):
    def __init__(self, routedict):
        self.routeinfo = routedict

class PluginCollection(object):
    def __init__(self, routedict):
        self.routeinfo = routedict

# _ prefix indicates internal use (e.g. special console scheme) and should not
# be enumerated in any collection
noderesources = {
    '_console': {
        'session': PluginRoute({
            'pluginattrs': ['console.method'],
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
    'health': {
        'hardware': PluginRoute({
            'pluginattrs': ['hardwaremanagement.method'],
            'default': 'ipmi',
        }),
    },
    'identify': PluginRoute({
        'pluginattrs': ['hardwaremanagement.method'],
        'default': 'ipmi',
    }),
    'boot': {
        'nextdevice': PluginRoute({
            'pluginattrs': ['hardwaremanagement.method'],
            'default': 'ipmi',
        }),
    },
    'attributes': {
        'all': PluginRoute({'handler': 'attributes'}),
        'current': PluginRoute({'handler': 'attributes'}),
    },
    'sensors': {
        'hardware': {
            'all': PluginCollection({
                'pluginattrs': ['hardwaremanagement.method'],
                'default': 'ipmi',
            }),
            'temperature': PluginCollection({
                'pluginattrs': ['hardwaremanagement.method'],
                'default': 'ipmi',
            }),
            'power': PluginCollection({
                'pluginattrs': ['hardwaremanagement.method'],
                'default': 'ipmi',
            }),
            'fans': PluginCollection({
                'pluginattrs': ['hardwaremanagement.method'],
                'default': 'ipmi',
            }),
        },
    },
}

nodegroupresources = {
    'attributes': {
        'all': PluginRoute({'handler': 'attributes'}),
        'current': PluginRoute({'handler': 'attributes'}),
    },
}


def create_user(inputdata, configmanager):
    try:
        username = inputdata['name']
        del inputdata['name']
    except (KeyError, ValueError):
        raise exc.InvalidArgumentException()
    configmanager.create_user(username, attributemap=inputdata)


def update_user(name, attribmap, configmanager):
    try:
        configmanager.set_user(name, attribmap)
    except ValueError:
        raise exc.InvalidArgumentException()


def show_user(name, configmanager):
    userobj = configmanager.get_user(name)
    rv = {}
    for attr in attrscheme.user.iterkeys():
        rv[attr] = None
        if attr == 'password':
            if 'cryptpass' in userobj:
                rv['password'] = {'cryptvalue': True}
            yield msg.CryptedAttributes(kv={'password': rv['password']},
                                        desc=attrscheme.user[attr][
                                            'description'])
        else:
            if attr in userobj:
                rv[attr] = userobj[attr]
            yield msg.Attributes(kv={attr: rv[attr]},
                                 desc=attrscheme.user[attr]['description'])


def stripnode(iterablersp, node):
    for i in iterablersp:
        if i is None:
            raise exc.NotImplementedException("Not Implemented")
        i.strip_node(node)
        yield i


def iterate_collections(iterable, forcecollection=True):
    for coll in iterable:
        if forcecollection and coll[-1] != '/':
            coll += '/'
        yield msg.ChildCollection(coll, candelete=True)


def iterate_resources(fancydict):
    for resource in fancydict.iterkeys():
        if resource.startswith("_"):
            continue
        if not isinstance(fancydict[resource], PluginRoute):  # a resource
            resource += '/'
        yield msg.ChildCollection(resource)


def delete_user(user, configmanager):
    configmanager.del_user(user)
    yield msg.DeletedResource(user)


def delete_nodegroup_collection(collectionpath, configmanager):
    if len(collectionpath) == 2:  # just the nodegroup
        group = collectionpath[-1]
        configmanager.del_groups([group])
        yield msg.DeletedResource(group)
    else:
        raise Exception("Not implemented")


def delete_node_collection(collectionpath, configmanager):
    if len(collectionpath) == 2:  # just node
        node = collectionpath[-1]
        configmanager.del_nodes([node])
        yield msg.DeletedResource(node)
    else:
        raise Exception("Not implemented")


def enumerate_nodegroup_collection(collectionpath, configmanager):
    nodegroup = collectionpath[1]
    if not configmanager.is_nodegroup(nodegroup):
        raise exc.NotFoundException("Invalid element requested")
    del collectionpath[0:2]
    collection = nested_lookup(nodegroupresources, collectionpath)
    return iterate_resources(collection)


def enumerate_node_collection(collectionpath, configmanager):
    if collectionpath == ['nodes']:  # it is just '/node/', need to list nodes
        return iterate_collections(configmanager.list_nodes())
    nodeorrange = collectionpath[1]
    if collectionpath[0] == 'nodes' and not configmanager.is_node(nodeorrange):
        raise exc.NotFoundException("Invalid element requested")
    collection = nested_lookup(noderesources, collectionpath[2:])
    if len(collectionpath) == 2 and collectionpath[0] == 'noderange':
        collection['nodes'] = {}
    if not isinstance(collection, dict):
        raise exc.NotFoundException("Invalid element requested")
    return iterate_resources(collection)


def create_group(inputdata, configmanager):
    try:
        groupname = inputdata['name']
        del inputdata['name']
        attribmap = {groupname: inputdata}
    except KeyError:
        raise exc.InvalidArgumentException()
    try:
        configmanager.add_group_attributes(attribmap)
    except ValueError as e:
        raise exc.InvalidArgumentException(str(e))


def create_node(inputdata, configmanager):
    try:
        nodename = inputdata['name']
        del inputdata['name']
        attribmap = {nodename: inputdata}
    except KeyError:
        raise exc.InvalidArgumentException('name not specified')
    try:
        configmanager.add_node_attributes(attribmap)
    except ValueError as e:
        raise exc.InvalidArgumentException(str(e))


def enumerate_collections(collections):
    for collection in collections:
        yield msg.ChildCollection(collection)


def handle_nodegroup_request(configmanager, inputdata,
                             pathcomponents, operation):
    iscollection = False
    if len(pathcomponents) < 2:
        if operation == "create":
            inputdata = msg.InputAttributes(pathcomponents, inputdata)
            create_group(inputdata.attribs, configmanager)
        return iterate_collections(configmanager.get_groups())
    elif len(pathcomponents) == 2:
        iscollection = True
    else:
        try:
            routespec = nested_lookup(nodegroupresources, pathcomponents[2:])
            if isinstance(routespec, dict):
                iscollection = True
            elif isinstance(routespec, PluginCollection):
                iscollection = False  # it is a collection, but plugin defined
        except KeyError:
            raise exc.NotFoundException("Invalid element requested")
    if iscollection:
        if operation == "delete":
            return delete_nodegroup_collection(pathcomponents,
                                                 configmanager)
        elif operation == "retrieve":
            return enumerate_nodegroup_collection(pathcomponents,
                                                    configmanager)
        else:
            raise Exception("TODO")
    plugroute = routespec.routeinfo
    inputdata = msg.get_input_message(
        pathcomponents[2:], operation, inputdata)
    if 'handler' in plugroute:  # fixed handler definition
        hfunc = getattr(pluginmap[plugroute['handler']], operation)
        return hfunc(
            nodes=None, element=pathcomponents,
            configmanager=configmanager,
            inputdata=inputdata)
    raise Exception("unknown case encountered")


def handle_node_request(configmanager, inputdata, operation,
                        pathcomponents):
    iscollection = False
    routespec = None
    if pathcomponents[0] == 'noderange':
        if len(pathcomponents) > 3 and pathcomponents[2] == 'nodes':
            # transform into a normal looking node request
            # this does mean we don't see if it is a valid
            # child, but that's not a goal for the noderange
            # facility anyway
            isnoderange = False
            pathcomponents = pathcomponents[2:]
        else:
            isnoderange = True
    else:
        isnoderange = False
    try:
        nodeorrange = pathcomponents[1]
        if not isnoderange and not configmanager.is_node(nodeorrange):
            raise exc.NotFoundException("Invalid Node")
        if isnoderange:
            try:
                nodes = noderange.NodeRange(nodeorrange, configmanager).nodes
            except Exception:
                raise exc.NotFoundException("Invalid Noderange")
        else:
            nodes = (nodeorrange,)
    except IndexError:  # doesn't actually have a long enough path
        # this is enumerating a list of nodes or just empty noderange
        if isnoderange and operation == "retrieve":
            return iterate_collections([])
        elif isnoderange or operation == "delete":
            raise exc.InvalidArgumentException()
        if operation == "create":
            inputdata = msg.InputAttributes(pathcomponents, inputdata)
            create_node(inputdata.attribs, configmanager)
        return iterate_collections(configmanager.list_nodes())
    if isnoderange and len(pathcomponents) == 3 and pathcomponents[2] == 'nodes':
        # this means that it's a list of relevant nodes
        return iterate_collections(nodes)
    if len(pathcomponents) == 2:
        iscollection = True
    else:
        try:
            routespec = nested_lookup(noderesources, pathcomponents[2:])
        except KeyError:
            raise exc.NotFoundException("Invalid element requested")
        if isinstance(routespec, dict):
            iscollection = True
        elif isinstance(routespec, PluginCollection):
            iscollection = False  # it is a collection, but plugin defined
    if iscollection:
        if operation == "delete":
            return delete_node_collection(pathcomponents, configmanager)
        elif operation == "retrieve":
            return enumerate_node_collection(pathcomponents, configmanager)
        else:
            raise Exception("TODO here")
    del pathcomponents[0:2]
    passvalues = []
    plugroute = routespec.routeinfo
    inputdata = msg.get_input_message(
        pathcomponents, operation, inputdata, nodes)
    if 'handler' in plugroute:  # fixed handler definition, easy enough
        hfunc = getattr(pluginmap[plugroute['handler']], operation)
        passvalue =hfunc(
            nodes=nodes, element=pathcomponents,
            configmanager=configmanager,
            inputdata=inputdata)
        if isnoderange:
            return passvalue
        else:
            return stripnode(passvalue, nodes[0])
    elif 'pluginattrs' in plugroute:
        nodeattr = configmanager.get_node_attributes(
            nodes, plugroute['pluginattrs'])
        plugpath = None
        if 'default' in plugroute:
            plugpath = plugroute['default']
        nodesbyhandler = {}
        for node in nodes:
            for attrname in plugroute['pluginattrs']:
                if attrname in nodeattr[node]:
                    plugpath = nodeattr[node][attrname]['value']
            if plugpath is not None:
                hfunc = getattr(pluginmap[plugpath], operation)
                if hfunc in nodesbyhandler:
                    nodesbyhandler[hfunc].append(node)
                else:
                    nodesbyhandler[hfunc] = [node]
        for hfunc in nodesbyhandler.iterkeys():
            passvalues.append(hfunc(
                nodes=nodesbyhandler[hfunc], element=pathcomponents,
                configmanager=configmanager,
                inputdata=inputdata))
        if isnoderange:
            return itertools.chain(*passvalues)
        elif isinstance(passvalues[0], console.Console):
            return passvalues[0]
        else:
            return stripnode(passvalues[0], nodes[0])

def handle_path(path, operation, configmanager, inputdata=None):
    """Given a full path request, return an object.

    The plugins should generally return some sort of iterator.
    An exception is made for console/session, which should return
    a class with connect(), read(), write(bytes), and close()
    """
    pathcomponents = path.split('/')
    del pathcomponents[0]  # discard the value from leading /
    if pathcomponents[-1] == '':
        del pathcomponents[-1]
    if not pathcomponents:  # root collection list
        return enumerate_collections(rootcollections)
    elif pathcomponents[0] == 'noderange':
        return handle_node_request(configmanager, inputdata, operation,
                                          pathcomponents)
    elif pathcomponents[0] == 'nodegroups':
        return handle_nodegroup_request(configmanager, inputdata,
                                          pathcomponents,
                                          operation)
    elif pathcomponents[0] == 'nodes':
        #single node request of some sort
        return handle_node_request(configmanager, inputdata,
                                     operation, pathcomponents)
    elif pathcomponents[0] == 'users':
        #TODO: when non-administrator accounts exist,
        # they must only be allowed to see their own user
        try:
            user = pathcomponents[1]
        except IndexError:  # it's just users/
            if operation == 'create':
                inputdata = msg.get_input_message(
                    pathcomponents, operation, inputdata)
                create_user(inputdata.attribs, configmanager)
            return iterate_collections(configmanager.list_users(),
                                       forcecollection=False)
        if user not in configmanager.list_users():
            raise exc.NotFoundException("Invalid user %s" % user)
        if operation == 'retrieve':
            return show_user(user, configmanager)
        elif operation == 'delete':
            return delete_user(user, configmanager)
        elif operation == 'update':
            inputdata = msg.get_input_message(
                pathcomponents, operation, inputdata)
            update_user(user, inputdata.attribs, configmanager)
            return show_user(user, configmanager)
    else:
        raise exc.NotFoundException()
