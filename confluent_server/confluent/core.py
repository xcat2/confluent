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
import confluent.shellmodule as shellmodule
import os
import sys

pluginmap = {}


def nested_lookup(nestdict, key):
    try:
        return reduce(dict.__getitem__, key, nestdict)
    except TypeError:
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


rootcollections = ['nodes/', 'groups/', 'users/']


class PluginRoute(object):
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
        if attr == 'passphrase':
            if 'cryptpass' in userobj:
                rv['passphrase'] = {'cryptvalue': True}
            yield msg.CryptedAttributes(kv={'passphrase': rv['passphrase']},
                                        desc=attrscheme.user[attr][
                                            'description'])
        else:
            if attr in userobj:
                rv[attr] = userobj[attr]
            yield msg.Attributes(kv={attr: rv[attr]},
                                 desc=attrscheme.user[attr]['description'])


def stripnode(iterablersp, node):
    for i in iterablersp:
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
    node = collectionpath[1]
    if not configmanager.is_node(node):
        raise exc.NotFoundException("Invalid element requested")
    del collectionpath[0:2]
    collection = nested_lookup(noderesources, collectionpath)
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


def handle_path(path, operation, configmanager, inputdata=None):
    """Given a full path request, return an object.

    The plugins should generally return some sort of iterator.
    An exception is made for console/session, which should return
    a class with connect(), read(), write(bytes), and close()
    """
    iscollection = False
    pathcomponents = path.split('/')
    del pathcomponents[0]  # discard the value from leading /
    if pathcomponents[-1] == '':
        iscollection = True
        del pathcomponents[-1]
    if not pathcomponents:  # root collection list
        return enumerate_collections(rootcollections)
    elif pathcomponents[0] == 'groups':
        if len(pathcomponents) < 2:
            if operation == "create":
                inputdata = msg.InputAttributes(pathcomponents, inputdata)
                create_group(inputdata.attribs, configmanager)
            return iterate_collections(configmanager.get_groups())
        if len(pathcomponents) == 2:
            iscollection = True
        if iscollection:
            if operation == "delete":
                return delete_nodegroup_collection(pathcomponents,
                                                   configmanager)
            elif operation == "retrieve":
                return enumerate_nodegroup_collection(pathcomponents,
                                                      configmanager)
            else:
                raise Exception("TODO")
        try:
            plugroute = nested_lookup(
                nodegroupresources, pathcomponents[2:]).routeinfo
        except KeyError:
            raise exc.NotFoundException("Invalid element requested")
        inputdata = msg.get_input_message(
            pathcomponents[2:], operation, inputdata)
        if 'handler' in plugroute:  # fixed handler definition
            hfunc = getattr(pluginmap[plugroute['handler']], operation)
            return hfunc(
                nodes=None, element=pathcomponents,
                configmanager=configmanager,
                inputdata=inputdata)
    elif pathcomponents[0] == 'nodes':
        #single node request of some sort
        try:
            node = pathcomponents[1]
        except IndexError:  # doesn't actually have a long enough path
            # this is enumerating a list of nodes
            if operation == "delete":
                raise exc.InvalidArgumentException()
            if operation == "create":
                inputdata = msg.InputAttributes(pathcomponents, inputdata)
                create_node(inputdata.attribs, configmanager)
            return iterate_collections(configmanager.list_nodes())
        if len(pathcomponents) == 2:
            iscollection = True
        if iscollection:
            if operation == "delete":
                return delete_node_collection(pathcomponents, configmanager)
            elif operation == "retrieve":
                return enumerate_node_collection(pathcomponents, configmanager)
            else:
                raise Exception("TODO here")
        del pathcomponents[0:2]
        passvalue = None
        try:
            plugroute = nested_lookup(noderesources, pathcomponents).routeinfo
        except KeyError:
            raise exc.NotFoundException("Invalid element requested")
        inputdata = msg.get_input_message(
            pathcomponents, operation, inputdata, (node,))
        if 'handler' in plugroute:  # fixed handler definition
            hfunc = getattr(pluginmap[plugroute['handler']], operation)
            passvalue = hfunc(
                nodes=(node,), element=pathcomponents,
                configmanager=configmanager,
                inputdata=inputdata)
        elif 'pluginattrs' in plugroute:
            nodeattr = configmanager.get_node_attributes(
                [node], plugroute['pluginattrs'])
            if node not in nodeattr:
                raise exc.NotFoundException("Invalid node %s" % node)
            plugpath = None
            if 'default' in plugroute:
                plugpath = plugroute['default']
            for attrname in plugroute['pluginattrs']:
                if attrname in nodeattr[node]:
                    plugpath = nodeattr[node][attrname]['value']
            if plugpath is not None:
                hfunc = getattr(pluginmap[plugpath], operation)
                passvalue = hfunc(
                    nodes=(node,), element=pathcomponents,
                    configmanager=configmanager,
                    inputdata=inputdata)
        if isinstance(passvalue, console.Console):
            return passvalue
        else:
            return stripnode(passvalue, node)
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
