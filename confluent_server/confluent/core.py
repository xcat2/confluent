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

import confluent
import confluent.alerts as alerts
import confluent.log as log
import confluent.tlvdata as tlvdata
import confluent.config.attributes as attrscheme
import confluent.config.configmanager as cfm
import confluent.collective.manager as collective
import confluent.discovery.core as disco
import confluent.interface.console as console
import confluent.exceptions as exc
import confluent.messages as msg
import confluent.networking.macmap as macmap
import confluent.noderange as noderange
import confluent.osimage as osimage
import confluent.plugin as plugin
try:
    import confluent.shellmodule as shellmodule
except ImportError:
    pass
try:
    import OpenSSL.crypto as crypto
except ImportError:
    # Only required for collective mode
    crypto = None
import confluent.util as util
import eventlet
import eventlet.greenpool as greenpool
import eventlet.green.ssl as ssl
import eventlet.queue as queue
import eventlet.semaphore as semaphore
import itertools
import msgpack
import os
import eventlet.green.socket as socket
import struct
import sys

pluginmap = {}
dispatch_plugins = (b'ipmi', u'ipmi', b'redfish', u'redfish', b'tsmsol', u'tsmsol', b'geist', u'geist', b'deltapdu', u'deltapdu', b'eatonpdu', u'eatonpdu', b'affluent', u'affluent', b'cnos', u'cnos')

PluginCollection = plugin.PluginCollection

try:
    unicode
except NameError:
    unicode = str

def seek_element(currplace, currkey, depth):
    try:
        return currplace[currkey]
    except TypeError:
        if isinstance(currplace, PluginCollection):
            # we hit a plugin curated collection, all children
            # are up to the plugin to comprehend
            if currplace.maxdepth and depth > currplace.maxdepth:
                raise
            return currplace
        raise


def nested_lookup(nestdict, key):
    try:
        currloc = nestdict
        for i in range(len(key)):
            currk = key[i]
            currloc = seek_element(currloc, currk, len(key) - i)
        return currloc
    except TypeError:
        raise exc.NotFoundException("Invalid element requested")


def load_plugins():
    # To know our plugins directory, we get the parent path of 'bin'
    _init_core()
    path = os.path.dirname(os.path.realpath(__file__))
    plugintop = os.path.realpath(os.path.join(path, 'plugins'))
    plugins = set()
    for plugindir in os.listdir(plugintop):
        plugindir = os.path.join(plugintop, plugindir)
        if not os.path.isdir(plugindir):
            continue
        sys.path.insert(1, plugindir)
        # two passes, to avoid adding both py and pyc files
        for plugin in os.listdir(plugindir):
            if plugin.startswith('.'):
                continue
            if '__pycache__' in plugin:
                continue
            (plugin, plugtype) = os.path.splitext(plugin)
            if plugtype == '.sh':
                pluginmap[plugin] = shellmodule.Plugin(
                    os.path.join(plugindir, plugin + '.sh'))
            elif "__init__" not in plugin:
                plugins.add(plugin)
        for plugin in plugins:
            tmpmod = __import__(plugin)
            if 'plugin_names' in tmpmod.__dict__:
                for name in tmpmod.plugin_names:
                    pluginmap[name] = tmpmod
            else:
                pluginmap[plugin] = tmpmod
                _register_resource(tmpmod)
        plugins.clear()
        # restore path to not include the plugindir
        sys.path.pop(1)
    disco.register_affluent(pluginmap['affluent'])


def _register_resource(plugin):
    global noderesources
    if 'custom_resources' in plugin.__dict__:
        _merge_dict(noderesources, plugin.custom_resources)


def _merge_dict(original, custom):
    for k,v in custom.items():
        if k in original:
            if isinstance(original.get(k), dict):
                _merge_dict(original.get(k), custom.get(k))
            else:
                original[k] = custom.get(k)
        else:
            original[k] = custom.get(k)


rootcollections = ['deployment/', 'discovery/', 'events/', 'networking/',
                   'noderange/', 'nodes/', 'nodegroups/', 'usergroups/' ,
                   'users/', 'uuid', 'version']


class PluginRoute(object):
    def __init__(self, routedict):
        self.routeinfo = routedict



def handle_deployment(configmanager, inputdata, pathcomponents,
                      operation):
    if len(pathcomponents) == 1:
        yield msg.ChildCollection('distributions/')
        yield msg.ChildCollection('profiles/')
        yield msg.ChildCollection('importing/')
        return
    if pathcomponents[1] == 'distributions':
        if len(pathcomponents) == 2 and operation == 'retrieve':
            for dist in osimage.list_distros():
                yield msg.ChildCollection(dist + '/')
            return
        if len(pathcomponents) == 3:
            distname = pathcomponents[-1]
            if 'operation' == 'update':
                if inputdata.get('rescan', False):
                    osimage.rescan_dist(distname)
    if pathcomponents[1] == 'profiles':
        if len(pathcomponents) == 2 and operation == 'retrieve':
            for prof in osimage.list_profiles():
                yield msg.ChildCollection(prof + '/')
            return
        if len(pathcomponents) == 3:
            profname = pathcomponents[-1]
            if operation == 'update':
                if 'updateboot' in inputdata:
                    osimage.update_boot(profname)
                    yield msg.KeyValueData({'updated': profname})
                    return
                elif 'rebase' in inputdata:
                    try:
                        updated, customized = osimage.rebase_profile(profname)
                    except osimage.ManifestMissing:
                        raise exc.InvalidArgumentException('Specified profile {0} does not have a manifest.yaml for rebase'.format(profname))
                    for upd in updated:
                        yield msg.KeyValueData({'updated': upd})                        
                    for cust in customized:
                        yield msg.KeyValueData({'customized': cust})
                    return
    if pathcomponents[1] == 'importing':
        if len(pathcomponents) == 2 or not pathcomponents[-1]:
            if operation == 'retrieve':
                for imp in osimage.list_importing():
                    yield imp
                return
            elif operation == 'create':
                importer = osimage.MediaImporter(inputdata['filename'],
                                                 configmanager)
                yield msg.KeyValueData({'target': importer.targpath,
                                        'name': importer.importkey})
                return
        elif len(pathcomponents) == 3:
            if operation == 'retrieve':
                for res in osimage.get_importing_status(pathcomponents[-1]):
                    yield res
                return
            elif operation == 'delete':
                for res in osimage.remove_importing(pathcomponents[-1]):
                    yield res
                return
    raise exc.NotFoundException('Unrecognized request')


def _init_core():
    global noderesources
    global nodegroupresources
    import confluent.shellserver as shellserver
    # _ prefix indicates internal use (e.g. special console scheme) and should not
    # be enumerated in any collection
    noderesources = {
        'attributes': {
            'rename': PluginRoute({'handler': 'attributes'}),
            'all': PluginRoute({'handler': 'attributes'}),
            'current': PluginRoute({'handler': 'attributes'}),
            'expression': PluginRoute({'handler': 'attributes'}),
        },
        'boot': {
            'nextdevice': PluginRoute({
                'pluginattrs': ['hardwaremanagement.method'],
                'default': 'ipmi',
            }),
        },
        'configuration': {
            'management_controller': {
                'alerts': {
                    'destinations': PluginCollection({
                        'pluginattrs': ['hardwaremanagement.method'],
                        'default': 'ipmi',
                    }),
                },
                'clear': PluginRoute({
                        'pluginattrs': ['hardwaremanagement.method'],
                        'default': 'ipmi',
                }),
                'users': PluginCollection({
                    'pluginattrs': ['hardwaremanagement.method'],
                    'default': 'ipmi',
                }),
                'licenses': PluginCollection({
                    'pluginattrs': ['hardwaremanagement.method'],
                    'default': 'ipmi',
                }),
                'save_licenses': PluginRoute({
                    'pluginattrs': ['hardwaremanagement.method'],
                    'default': 'ipmi',
                }),
                'net_interfaces': PluginCollection({
                    'pluginattrs': ['hardwaremanagement.method'],
                    'default': 'ipmi',
                }),
                'reset': PluginRoute({
                    'pluginattrs': ['hardwaremanagement.method'],
                    'default': 'ipmi',
                }),
                'hostname': PluginRoute({
                    'pluginattrs': ['hardwaremanagement.method'],
                    'default': 'ipmi',
                }),
                'identifier': PluginRoute({
                    'pluginattrs': ['hardwaremanagement.method'],
                    'default': 'ipmi',
                }),
                'domain_name': PluginRoute({
                    'pluginattrs': ['hardwaremanagement.method'],
                    'default': 'ipmi',
                }),
                'location': PluginRoute({
                    'pluginattrs': ['hardwaremanagement.method'],
                    'default': 'ipmi',
                }),
                'ntp': {
                    'enabled': PluginRoute({
                        'pluginattrs': ['hardwaremanagement.method'],
                        'default': 'ipmi',
                    }),
                    'servers': PluginCollection({
                        'pluginattrs': ['hardwaremanagement.method'],
                        'default': 'ipmi',
                    }),
                },
                'extended': {
                    'all': PluginRoute({
                        'pluginattrs': ['hardwaremanagement.method'],
                        'default': 'ipmi',
                    }),
                    'extra': PluginRoute({
                        'pluginattrs': ['hardwaremanagement.method'],
                        'default': 'ipmi',
                    }),
                    'advanced': PluginRoute({
                        'pluginattrs': ['hardwaremanagement.method'],
                        'default': 'ipmi',
                    }),
                },
            },
            'storage': {
                'all': PluginRoute({
                    'pluginattrs': ['hardwaremanagement.method'],
                    'default': 'ipmi',
                }),
                'arrays': PluginCollection({
                    'pluginattrs': ['hardwaremanagement.method'],
                    'default': 'ipmi',
                }),
                'disks': PluginCollection({
                    'pluginattrs': ['hardwaremanagement.method'],
                    'default': 'ipmi',
                }),
                'volumes': PluginCollection({
                    'pluginattrs': ['hardwaremanagement.method'],
                    'default': 'ipmi',
                })
            },
            'system': {
                'all': PluginRoute({
                    'pluginattrs': ['hardwaremanagement.method'],
                    'default': 'ipmi',
                }),
                'advanced': PluginRoute({
                    'pluginattrs': ['hardwaremanagement.method'],
                    'default': 'ipmi',
                }),
                'clear': PluginRoute({
                    'pluginattrs': ['hardwaremanagement.method'],
                    'default': 'ipmi',
                })
            },
        },
        '_console': {
            'session': PluginRoute({
                'pluginattrs': ['console.method'],
            }),
        },
        '_shell': {
            'session': PluginRoute({
                # For now, not configurable, wait until there's demand
                'handler': 'ssh',
            }),
        },
        '_enclosure': {
            'reseat_bay': PluginRoute(
                {'pluginattrs': ['hardwaremanagement.method'],
                 'default': 'ipmi'}),
        },
        'shell': {
            # another special case similar to console
            'sessions': PluginCollection({
                    'handler': shellserver,
            }),
        },
        'console': {
            # this is a dummy value, http or socket must handle special
            'session': None,
            'license': PluginRoute({
                'pluginattrs': ['hardwaremanagement.method'],
                'default': 'ipmi',
            }),
            'graphical': PluginRoute({
                'pluginattrs': ['hardwaremanagement.method'],
                'default': 'ipmi',
            }),
        },
        'description': PluginRoute({
            'pluginattrs': ['hardwaremanagement.method'],
            'default': 'ipmi',
        }),
        'deployment': {
            'ident_image': PluginRoute({
                'handler': 'identimage'
            })
        },
        'events': {
            'hardware': {
                'log': PluginRoute({
                    'pluginattrs': ['hardwaremanagement.method'],
                    'default': 'ipmi',
                }),
                'decode': PluginRoute({
                    'pluginattrs': ['hardwaremanagement.method'],
                    'default': 'ipmi',
                }),
            },
        },
        #'forward': {
        #    # Another dummy value, currently only for the gui
        #    'web': None,
        #},
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
        'inventory': {
            'hardware': {
                'all': PluginCollection({
                    'pluginattrs': ['hardwaremanagement.method'],
                    'default': 'ipmi',
                }),
            },
            'firmware': {
                'all': PluginCollection({
                    'pluginattrs': ['hardwaremanagement.method'],
                    'default': 'ipmi',
                }),
                'updates': {
                    'active': PluginCollection({
                            'pluginattrs': ['hardwaremanagement.method'],
                            'default': 'ipmi',
                    }),
                },
            },
        },
        'media': {
            'uploads': PluginCollection({
                'pluginattrs': ['hardwaremanagement.method'],
                'default': 'ipmi',
            }),
            'attach': PluginRoute({
                'pluginattrs': ['hardwaremanagement.method'],
                'default': 'ipmi',
            }),
            'detach': PluginRoute({
                'pluginattrs': ['hardwaremanagement.method'],
                'default': 'ipmi',
            }),
            'current': PluginRoute({
                'pluginattrs': ['hardwaremanagement.method'],
                'default': 'ipmi',
            }),

        },
        'power': {
            'state': PluginRoute({
                'pluginattrs': ['hardwaremanagement.method'],
                'default': 'ipmi',
            }),
            'inlets': PluginCollection({'handler': 'pdu'}),
            'outlets': PluginCollection({'pluginattrs': ['hardwaremanagement.method']}),
            'reseat':  PluginRoute({'handler': 'enclosure'}),
        },
        'sensors': {
            'hardware': {
                'all': PluginCollection({
                    'pluginattrs': ['hardwaremanagement.method'],
                    'default': 'ipmi',
                }),
                'energy': PluginCollection({
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
                'leds': PluginCollection({
                    'pluginattrs': ['hardwaremanagement.method'],
                    'default': 'ipmi',
                }),
            },

        },
        'support': {
            'servicedata': PluginCollection({
                'pluginattrs': ['hardwaremanagement.method'],
                'default': 'ipmi',
            }),
        },
    }

    nodegroupresources = {
        'attributes': {
            'check': PluginRoute({'handler': 'attributes'}),
            'rename': PluginRoute({'handler': 'attributes'}),
            'all': PluginRoute({'handler': 'attributes'}),
            'current': PluginRoute({'handler': 'attributes'}),
        },
    }


def create_user(inputdata, configmanager):
    try:
        username = inputdata['name']
        del inputdata['name']
        role = inputdata['role']
        del inputdata['role']
    except (KeyError, ValueError):
        raise exc.InvalidArgumentException('Missing user name or role')
    configmanager.create_user(username, role, attributemap=inputdata)


def create_usergroup(inputdata, configmanager):
    try:
        groupname = inputdata['name']
        role = inputdata['role']
        del inputdata['name']
        del inputdata['role']
    except (KeyError, ValueError):
        raise exc.InvalidArgumentException("Missing user name or role")
    configmanager.create_usergroup(groupname, role)


def update_usergroup(groupname, attribmap, configmanager):
    try:
        configmanager.set_usergroup(groupname, attribmap)
    except ValueError as e:
        raise exc.InvalidArgumentException(str(e))

def update_user(name, attribmap, configmanager):
    try:
        configmanager.set_user(name, attribmap)
    except ValueError as e:
        raise exc.InvalidArgumentException(str(e))


def show_usergroup(groupname, configmanager):
    groupinfo = configmanager.get_usergroup(groupname)
    for attr in groupinfo:
        yield msg.Attributes(kv={attr: groupinfo[attr]})

def show_user(name, configmanager):
    userobj = configmanager.get_user(name)
    rv = {}
    for attr in attrscheme.user:
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
    if 'role' in userobj:
        yield msg.Attributes(kv={'role': userobj['role']})




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
    for resource in fancydict:
        if resource.startswith("_"):
            continue
        if resource == 'abbreviate':
            pass
        elif not isinstance(fancydict[resource], PluginRoute):  # a resource
            resource += '/'
        yield msg.ChildCollection(resource)


def delete_user(user, configmanager):
    configmanager.del_user(user)
    yield msg.DeletedResource(user)

def delete_usergroup(usergroup, configmanager):
    configmanager.del_usergroup(usergroup)
    yield msg.DeletedResource(usergroup)


def delete_nodegroup_collection(collectionpath, configmanager):
    if len(collectionpath) == 2:  # just the nodegroup
        group = collectionpath[-1]
        configmanager.del_groups([group])
        yield msg.DeletedResource(group)
    else:
        raise Exception("Not implemented")


def delete_node_collection(collectionpath, configmanager, isnoderange):
    if len(collectionpath) == 2:  # just node
        nodes = [collectionpath[-1]]
        if isnoderange:
            nodes = noderange.NodeRange(nodes[0], configmanager).nodes
        configmanager.del_nodes(nodes)
        for node in nodes:
            yield msg.DeletedResource(node)
    else:
        raise Exception("Not implemented")


def enumerate_nodegroup_collection(collectionpath, configmanager):
    nodegroup = collectionpath[1]
    if not configmanager.is_nodegroup(nodegroup):
        raise exc.NotFoundException(
            'Invalid nodegroup: {0} not found'.format(nodegroup))
    del collectionpath[0:2]
    collection = nested_lookup(nodegroupresources, collectionpath)
    return iterate_resources(collection)


def enumerate_node_collection(collectionpath, configmanager):
    if collectionpath == ['nodes']:  # it is just '/node/', need to list nodes
        allnodes = list(configmanager.list_nodes())
        try:
            allnodes.sort(key=noderange.humanify_nodename)
        except TypeError:
            allnodes.sort()
        return iterate_collections(allnodes)
    nodeorrange = collectionpath[1]
    if collectionpath[0] == 'nodes' and not configmanager.is_node(nodeorrange):
        raise exc.NotFoundException("Invalid element requested")
    collection = nested_lookup(noderesources, collectionpath[2:])
    if len(collectionpath) == 2 and collectionpath[0] == 'noderange':
        collection['nodes'] = {}
        collection['abbreviate'] = {}
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
    yield msg.CreatedResource(groupname)


def create_node(inputdata, configmanager):
    try:
        nodename = inputdata['name']
        if ' ' in nodename:
            raise exc.InvalidArgumentException('Name "{0}" is not supported'.format(nodename))
        del inputdata['name']
        attribmap = {nodename: inputdata}
    except KeyError:
        raise exc.InvalidArgumentException('name not specified')
    try:
        configmanager.add_node_attributes(attribmap)
    except ValueError as e:
        raise exc.InvalidArgumentException(str(e))
    yield msg.CreatedResource(nodename)


def create_noderange(inputdata, configmanager):
    try:
        noder = inputdata['name']
        del inputdata['name']
        attribmap = {}
        for node in noderange.NodeRange(noder).nodes:
            attribmap[node] = inputdata
    except KeyError:
        raise exc.InvalidArgumentException('name not specified')
    try:
        configmanager.add_node_attributes(attribmap)
    except ValueError as e:
        raise exc.InvalidArgumentException(str(e))
    for node in attribmap:
        yield msg.CreatedResource(node)



def enumerate_collections(collections):
    for collection in collections:
        yield msg.ChildCollection(collection)


def handle_nodegroup_request(configmanager, inputdata,
                             pathcomponents, operation):
    iscollection = False
    routespec = None
    if len(pathcomponents) < 2:
        if operation == "create":
            inputdata = msg.InputAttributes(pathcomponents, inputdata)
            return create_group(inputdata.attribs, configmanager)
        allgroups = list(configmanager.get_groups())
        try:
            allgroups.sort(key=noderange.humanify_nodename)
        except TypeError:
            allgroups.sort()
        return iterate_collections(allgroups)
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


class BadPlugin(object):
    def __init__(self, node, plugin):
        self.node = node
        self.plugin = plugin

    def error(self, *args, **kwargs):
        yield msg.ConfluentNodeError(
            self.node, self.plugin + ' is not a supported plugin')


class BadCollective(object):
    def __init__(self, node):
        self.node = node

    def error(self, *args, **kwargs):
        yield msg.ConfluentNodeError(
            self.node, 'collective mode is active, but collective.manager '
                       'is not set for this node')

def abbreviate_noderange(configmanager, inputdata, operation):
    if operation != 'create':
        raise exc.InvalidArgumentException('Must be a create with nodes in list')
    if 'nodes' not in inputdata:
        raise exc.InvalidArgumentException('Must be given list of nodes under key named nodes')
    if isinstance(inputdata['nodes'], str) or isinstance(inputdata['nodes'], unicode):
        inputdata['nodes'] = inputdata['nodes'].split(',')
    return (msg.KeyValueData({'noderange': noderange.ReverseNodeRange(inputdata['nodes'], configmanager).noderange}),)


def _keepalivefn(connection, xmitlock):
    while True:
        eventlet.sleep(30)
        with xmitlock:
            connection.sendall(b'\x00\x00\x00\x00\x00\x00\x00\x01\x00')

def handle_dispatch(connection, cert, dispatch, peername):
    cert = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
    if not util.cert_matches(
            cfm.get_collective_member(peername)['fingerprint'], cert):
        connection.close()
        return
    if dispatch[0:2] != b'\x01\x03':  # magic value to indicate msgpack
        # We only support msgpack now
        # The magic should preclude any pickle, as the first byte can never be
        # under 0x20 or so.
        connection.close()
        return
    xmitlock = semaphore.Semaphore()
    keepalive = eventlet.spawn(_keepalivefn, connection, xmitlock)
    dispatch = msgpack.unpackb(dispatch[2:], raw=False)
    configmanager = cfm.ConfigManager(dispatch['tenant'])
    nodes = dispatch['nodes']
    inputdata = dispatch['inputdata']
    operation = dispatch['operation']
    pathcomponents = dispatch['path']
    routespec = nested_lookup(noderesources, pathcomponents)
    try:
        inputdata = msg.get_input_message(
            pathcomponents, operation, inputdata, nodes, dispatch['isnoderange'],
            configmanager)
    except Exception as res:
        with xmitlock:
            _forward_rsp(connection, res)
        keepalive.kill()
        connection.sendall('\x00\x00\x00\x00\x00\x00\x00\x00')
        connection.close()
        return
    plugroute = routespec.routeinfo
    nodesbyhandler = {}
    passvalues = []
    nodeattr = configmanager.get_node_attributes(
        nodes, plugroute['pluginattrs'])
    for node in nodes:
        plugpath = None
        for attrname in plugroute['pluginattrs']:
            if attrname in nodeattr[node]:
                plugpath = nodeattr[node][attrname]['value']
            if not plugpath and 'default' in plugroute:
                plugpath = plugroute['default'] 
        if plugpath:
            try:
                hfunc = getattr(pluginmap[plugpath], operation)
            except KeyError:
                nodesbyhandler[BadPlugin(node, plugpath).error] = [node]
                continue
            if hfunc in nodesbyhandler:
                nodesbyhandler[hfunc].append(node)
            else:
                nodesbyhandler[hfunc] = [node]
    try:
        for hfunc in nodesbyhandler:
            passvalues.append(hfunc(
                nodes=nodesbyhandler[hfunc], element=pathcomponents,
                configmanager=configmanager,
                inputdata=inputdata))
        for res in itertools.chain(*passvalues):
            with xmitlock:
                _forward_rsp(connection, res)
    except Exception as res:
        with xmitlock:
            _forward_rsp(connection, res)
    keepalive.kill()
    connection.sendall('\x00\x00\x00\x00\x00\x00\x00\x00')
    connection.close()


def _forward_rsp(connection, res):
    try:
       r = res.serialize()
    except AttributeError:
        if isinstance(res, Exception):
            r = msgpack.packb(['Exception', str(res)], use_bin_type=False)
        else:
            r = msgpack.packb(
                ['Exception', 'Unable to serialize response ' + repr(res)],
                use_bin_type=False)
    except Exception as e:
        r = msgpack.packb(
                ['Exception', 'Unable to serialize response ' + repr(res) + ' due to ' + str(e)],
                use_bin_type=False)
    rlen = len(r)
    if not rlen:
        return
    connection.sendall(struct.pack('!Q', rlen))
    connection.sendall(r)


def handle_node_request(configmanager, inputdata, operation,
                        pathcomponents, autostrip=True):
    if log.logfull:
        raise exc.TargetResourceUnavailable('Filesystem full, free up space and restart confluent service')
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
        elif len(pathcomponents) == 3 and pathcomponents[2] == 'abbreviate':
            return abbreviate_noderange(configmanager, inputdata, operation)
        else:
            isnoderange = True
    else:
        isnoderange = False
    try:
        nodeorrange = pathcomponents[1]
        if not isnoderange and not configmanager.is_node(nodeorrange):
            raise exc.NotFoundException("Invalid Node")
        if isnoderange and not (len(pathcomponents) == 3 and
                                        pathcomponents[2] == 'abbreviate'):
            try:
                nodes = noderange.NodeRange(nodeorrange, configmanager).nodes
            except Exception as e:
                raise exc.NotFoundException("Invalid Noderange: " + str(e))
        else:
            nodes = (nodeorrange,)
    except IndexError:  # doesn't actually have a long enough path
        # this is enumerating a list of nodes or just empty noderange
        if isnoderange and operation == "retrieve":
            return iterate_collections([])
        elif isnoderange and operation == "create":
            inputdata = msg.InputAttributes(pathcomponents, inputdata)
            return create_noderange(inputdata.attribs, configmanager)
        elif isnoderange or operation == "delete":
            raise exc.InvalidArgumentException()
        if operation == "create":
            inputdata = msg.InputAttributes(pathcomponents, inputdata)
            return create_node(inputdata.attribs, configmanager)
        allnodes = list(configmanager.list_nodes())
        try:
            allnodes.sort(key=noderange.humanify_nodename)
        except TypeError:
            allnodes.sort()
        return iterate_collections(allnodes)
    if (isnoderange and len(pathcomponents) == 3 and
            pathcomponents[2] == 'nodes'):
        # this means that it's a list of relevant nodes
        nodes = list(nodes)
        try:
            nodes.sort(key=noderange.humanify_nodename)
        except TypeError:
            nodes.sort()
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
        elif routespec is None:
            raise exc.InvalidArgumentException('Custom interface required for resource')
    if iscollection:
        if operation == "delete":
            return delete_node_collection(pathcomponents, configmanager,
                                          isnoderange)
        elif operation == "retrieve":
            return enumerate_node_collection(pathcomponents, configmanager)
        else:
            raise Exception("TODO here")
    del pathcomponents[0:2]
    passvalues = queue.Queue()
    plugroute = routespec.routeinfo
    _plugin = None

    if 'handler' in plugroute:  # fixed handler definition, easy enough
        if isinstance(plugroute['handler'], str):
            hfunc = getattr(pluginmap[plugroute['handler']], operation)
            _plugin = pluginmap[plugroute['handler']]
        else:
            hfunc = getattr(plugroute['handler'], operation)
            _plugin = plugroute['handler']
        msginputdata = _get_input_data(_plugin, pathcomponents, operation,
                                       inputdata, nodes, isnoderange,
                                       configmanager)
        passvalue = hfunc(
            nodes=nodes, element=pathcomponents,
            configmanager=configmanager,
            inputdata=msginputdata)
        if isnoderange:
            return passvalue
        elif isinstance(passvalue, console.Console):
            return [passvalue]
        else:
            return stripnode(passvalue, nodes[0])
    elif 'pluginattrs' in plugroute:
        nodeattr = configmanager.get_node_attributes(
            nodes, plugroute['pluginattrs'] + ['collective.manager'])
        nodesbymanager = {}
        nodesbyhandler = {}
        badcollnodes = []
        for node in nodes:
            plugpath = None
            for attrname in plugroute['pluginattrs']:
                if attrname in nodeattr[node]:
                    plugpath = nodeattr[node][attrname]['value']
                if not plugpath and 'default' in plugroute:
                    plugpath = plugroute['default']
            if plugpath in dispatch_plugins:
                cfm.check_quorum()
                manager = nodeattr[node].get('collective.manager', {}).get(
                    'value', None)
                if manager:
                    if collective.get_myname() != manager:
                        if manager not in nodesbymanager:
                            nodesbymanager[manager] = set([node])
                        else:
                            nodesbymanager[manager].add(node)
                        continue
                elif list(cfm.list_collective()):
                    badcollnodes.append(node)
                    continue
            if plugpath:
                try:
                    _plugin = pluginmap[plugpath]
                    hfunc = getattr(pluginmap[plugpath], operation)
                except KeyError:
                    nodesbyhandler[BadPlugin(node, plugpath).error] = [node]
                    continue
                if hfunc in nodesbyhandler:
                    nodesbyhandler[hfunc].append(node)
                else:
                    nodesbyhandler[hfunc] = [node]
        for bn in badcollnodes:
            nodesbyhandler[BadCollective(bn).error] = [bn]
        workers = greenpool.GreenPool()
        numworkers = 0
        for hfunc in nodesbyhandler:
            numworkers += 1
            workers.spawn(addtoqueue, passvalues, hfunc, {'nodes': nodesbyhandler[hfunc],
                                           'element': pathcomponents,
                'configmanager': configmanager,
                'inputdata': _get_input_data(_plugin, pathcomponents,
                                             operation, inputdata,nodes,
                                             isnoderange, configmanager)})
        for manager in nodesbymanager:
            numworkers += 1
            workers.spawn(addtoqueue, passvalues, dispatch_request, {
                'nodes': nodesbymanager[manager], 'manager': manager,
                'element': pathcomponents, 'configmanager': configmanager,
                'inputdata': inputdata, 'operation': operation, 'isnoderange': isnoderange})
        if isnoderange or not autostrip:
            return iterate_queue(numworkers, passvalues)
        else:
            if numworkers > 0:
                return iterate_queue(numworkers, passvalues, nodes[0])
            else:
                raise exc.NotImplementedException()

        # elif isinstance(passvalues[0], console.Console):
        #     return passvalues[0]
        # else:
        #     return stripnode(passvalues[0], nodes[0])


def _get_input_data(plugin_ext, pathcomponents, operation, inputdata,
                   nodes, isnoderange, configmanager):
    if plugin_ext is not None and hasattr(plugin_ext, 'get_input_message'):
        return plugin_ext.get_input_message(pathcomponents, operation,
                                            inputdata, nodes, isnoderange,
                                            configmanager)
    else:
        return msg.get_input_message(pathcomponents, operation, inputdata,
                                     nodes, isnoderange,configmanager)


def iterate_queue(numworkers, passvalues, strip=False):
    completions = 0
    while completions < numworkers:
        nv = passvalues.get()
        if nv == 'theend':
            completions += 1
        else:
            if isinstance(nv, Exception):
                raise nv
            if strip and not isinstance(nv, console.Console):
                nv.strip_node(strip)
            yield nv


def addtoqueue(theq, fun, kwargs):
    try:
        result = fun(**kwargs)
        if isinstance(result, console.Console):
            theq.put(result)
        else:
            for pv in result:
                theq.put(pv)
    except Exception as e:
        theq.put(e)
    finally:
        theq.put('theend')


def dispatch_request(nodes, manager, element, configmanager, inputdata,
                     operation, isnoderange):
    a = configmanager.get_collective_member(manager)
    try:
        remote = socket.create_connection((a['address'], 13001))
        remote.settimeout(180)
        remote = ssl.wrap_socket(remote, cert_reqs=ssl.CERT_NONE,
                                 keyfile='/etc/confluent/privkey.pem',
                                 certfile='/etc/confluent/srvcert.pem')
    except Exception as e:
        for node in nodes:
            if a:
                yield msg.ConfluentResourceUnavailable(
                    node, 'Collective member {0} is unreachable ({1})'.format(
                        a['name'], str(e)))
            else:
                yield msg.ConfluentResourceUnavailable(
                    node,
                    '"{0}" is not recognized as a collective member'.format(
                        manager))

        return
    if not util.cert_matches(a['fingerprint'], remote.getpeercert(
            binary_form=True)):
        raise Exception("Invalid certificate on peer")
    banner = tlvdata.recv(remote)
    vers = banner.split()[2]
    if vers == b'v0':
        pvers = 2
    elif vers == b'v1':
        pvers = 4
    if sys.version_info[0] < 3:
        pvers = 2
    tlvdata.recv(remote)
    myname = collective.get_myname()
    dreq =  b'\x01\x03' + msgpack.packb(
        {'name': myname, 'nodes': list(nodes),
        'path': element,'tenant': configmanager.tenant,
        'operation': operation, 'inputdata': inputdata, 'isnoderange': isnoderange}, use_bin_type=False)
    tlvdata.send(remote, {'dispatch': {'name': myname, 'length': len(dreq)}})
    remote.sendall(dreq)
    while True:
        try:
            rlen = remote.recv(8)
        except Exception:
            for node in nodes:
                yield msg.ConfluentResourceUnavailable(
                    node, 'Collective member {0} went unreachable'.format(
                        a['name']))
            return
        while len(rlen) < 8:
            try:
                nlen = remote.recv(8 - len(rlen))
            except Exception:
                nlen = 0
            if not nlen:
                for node in nodes:
                    yield msg.ConfluentResourceUnavailable(
                        node, 'Collective member {0} went unreachable'.format(
                            a['name']))
                return
            rlen += nlen
        rlen = struct.unpack('!Q', rlen)[0]
        if rlen == 0:
            break
        try:
            rsp = remote.recv(rlen)
        except Exception:
            for node in nodes:
                yield msg.ConfluentResourceUnavailable(
                    node, 'Collective member {0} went unreachable'.format(
                        a['name']))
            return
        while len(rsp) < rlen:
            try:
                nrsp = remote.recv(rlen - len(rsp))
            except Exception:
                nrsp = 0
            if not nrsp:
                for node in nodes:
                    yield msg.ConfluentResourceUnavailable(
                        node, 'Collective member {0} went unreachable'.format(
                            a['name']))
                return
            rsp += nrsp
        if rsp == b'\x00':
            continue
        try:
            rsp = msg.msg_deserialize(rsp)
        except Exception:
            rsp = exc.deserialize_exc(rsp)
        if isinstance(rsp, Exception):
            raise rsp
        if not rsp:
            raise Exception('Error in cross-collective serialize/deserialze, see remote logs')
        yield rsp


def handle_discovery(pathcomponents, operation, configmanager, inputdata):
    if pathcomponents[0] == 'detected':
        pass

def handle_path(path, operation, configmanager, inputdata=None, autostrip=True):
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
                                   pathcomponents, autostrip)
    elif pathcomponents[0] == 'deployment':
        return handle_deployment(configmanager, inputdata, pathcomponents,
                                 operation)
    elif pathcomponents[0] == 'nodegroups':
        return handle_nodegroup_request(configmanager, inputdata,
                                        pathcomponents,
                                        operation)
    elif pathcomponents[0] == 'nodes':
        # single node request of some sort
        return handle_node_request(configmanager, inputdata,
                                   operation, pathcomponents, autostrip)
    elif pathcomponents[0] == 'discovery':
        return disco.handle_api_request(
            configmanager, inputdata, operation, pathcomponents)
    elif pathcomponents[0] == 'networking':
        return macmap.handle_api_request(
            configmanager, inputdata, operation, pathcomponents)
    elif pathcomponents[0] == 'version':
        return (msg.Attributes(kv={'version': confluent.__version__}),)
    elif pathcomponents[0] == 'uuid':
        if operation == 'update':
             with open('/var/lib/confluent/public/site/confluent_uuid', 'r') as uuidf:
                fsuuid = uuidf.read().strip()
                cfm.set_global('confluent_uuid', fsuuid)
        return (msg.Attributes(kv={'uuid': cfm.get_global('confluent_uuid')}),)
    elif pathcomponents[0] == 'usergroups':
        # TODO: when non-administrator accounts exist,
        # they must only be allowed to see their own user
        try:
            usergroup = pathcomponents[1]
        except IndexError:  # it's just users/
            if operation == 'create':
                inputdata = msg.get_input_message(
                    pathcomponents, operation, inputdata,
                    configmanager=configmanager)
                create_usergroup(inputdata.attribs, configmanager)
            return iterate_collections(configmanager.list_usergroups(),
                                       forcecollection=False)
        if usergroup not in configmanager.list_usergroups():
            raise exc.NotFoundException("Invalid usergroup %s" % usergroup)
        if operation == 'retrieve':
            return show_usergroup(usergroup, configmanager)
        elif operation == 'delete':
            return delete_usergroup(usergroup, configmanager)
        elif operation == 'update':
            inputdata = msg.get_input_message(
                pathcomponents, operation, inputdata,
                configmanager=configmanager)
            update_usergroup(usergroup, inputdata.attribs, configmanager)
            return show_usergroup(usergroup, configmanager)
    elif pathcomponents[0] == 'users':
        # TODO: when non-administrator accounts exist,
        # they must only be allowed to see their own user
        try:
            user = pathcomponents[1]
        except IndexError:  # it's just users/
            if operation == 'create':
                inputdata = msg.get_input_message(
                    pathcomponents, operation, inputdata,
                    configmanager=configmanager)
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
                pathcomponents, operation, inputdata,
                configmanager=configmanager)
            update_user(user, inputdata.attribs, configmanager)
            return show_user(user, configmanager)
    elif pathcomponents[0] == 'events':
        try:
            element = pathcomponents[1]
        except IndexError:
            if operation != 'retrieve':
                raise exc.InvalidArgumentException('Target is read-only')
            return (msg.ChildCollection('decode'),)
        if element != 'decode':
            raise exc.NotFoundException()
        if operation == 'update':
            return alerts.decode_alert(inputdata, configmanager)
    elif pathcomponents[0] == 'discovery':
        return handle_discovery(pathcomponents[1:], operation, configmanager,
                                inputdata)
    else:
        raise exc.NotFoundException()
