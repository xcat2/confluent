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

import confluent.exceptions as exc
import confluent.messages as msg
import confluent.config.attributes as allattributes


def retrieve(nodes, element, configmanager, inputdata):
    if nodes is not None:
        return retrieve_nodes(nodes, element, configmanager, inputdata)
    elif element[0] == 'groups':
        return retrieve_nodegroup(
            element[1], element[3], configmanager, inputdata)


def retrieve_nodegroup(nodegroup, element, configmanager, inputdata):
    grpcfg = configmanager.get_nodegroup_attributes(nodegroup)
    if element == 'all':
        nodes = []
        if 'nodes' in grpcfg:
            nodes = list(grpcfg['nodes'])
        yield msg.ListAttributes(kv={'nodes': nodes},
                                 desc="The nodes belonging to this group")
        for attribute in sorted(allattributes.node.iterkeys()):
            if attribute == 'groups':
                continue
            if attribute in grpcfg:
                val = grpcfg[attribute]
            else:
                val = {'value': None}
            if attribute.startswith('secret.'):
                yield msg.CryptedAttributes(
                    kv={attribute: val},
                    desc=allattributes.node[attribute]['description'])
            elif isinstance(val, list):
                raise Exception("TODO")
            else:
                yield msg.Attributes(
                    kv={attribute: val},
                    desc=allattributes.node[attribute]['description'])
    if element == 'current':
        for attribute in sorted(grpcfg.iterkeys()):
            currattr = grpcfg[attribute]
            if attribute == 'nodes':
                desc = 'The nodes belonging to this group'
            else:
                try:
                    desc = allattributes.node[attribute]['description']
                except KeyError:
                    desc = 'Unknown'
            if 'value' in currattr or 'expression' in currattr:
                yield msg.Attributes(kv={attribute: currattr}, desc=desc)
            elif 'cryptvalue' in currattr:
                yield msg.CryptedAttributes(
                    kv={attribute: currattr},
                    desc=desc)
            elif isinstance(currattr, set):
                yield msg.ListAttributes(
                    kv={attribute: list(currattr)},
                    desc=desc)
            elif isinstance(currattr, list):
                yield msg.ListAttributes(
                    kv={attribute: currattr},
                    desc=desc)
            else:
                print attribute
                print repr(currattr)
                raise Exception("BUGGY ATTRIBUTE FOR NODEGROUP")


def retrieve_nodes(nodes, element, configmanager, inputdata):
    attributes = configmanager.get_node_attributes(nodes)
    if element[-1] == 'all':
        for node in nodes:
            for attribute in sorted(allattributes.node.iterkeys()):
                if attribute in attributes[node]:  # have a setting for it
                    val = attributes[node][attribute]
                elif attribute == 'groups':  # no setting, provide a blank
                    val = []
                else:  # no setting, provide a blank
                    val = {'value': None}
                if attribute.startswith('secret.'):
                    yield msg.CryptedAttributes(
                        node, {attribute: val},
                        allattributes.node[attribute]['description'])
                elif isinstance(val, list):
                    yield msg.ListAttributes(
                        node, {attribute: val},
                        allattributes.node[attribute]['description'])
                else:
                    yield msg.Attributes(
                        node, {attribute: val},
                        allattributes.node[attribute]['description'])
    elif element[-1] == 'current':
        for node in attributes.iterkeys():
            for attribute in sorted(attributes[node].iterkeys()):
                currattr = attributes[node][attribute]
                try:
                    desc = allattributes.node[attribute]['description']
                except KeyError:
                    desc = 'Unknown'
                if 'value' in currattr or 'expression' in currattr:
                    yield msg.Attributes(node, {attribute: currattr}, desc)
                elif 'cryptvalue' in currattr:
                    yield msg.CryptedAttributes(
                        node, {attribute: currattr}, desc)
                elif isinstance(currattr, list):
                    yield msg.ListAttributes(
                        node, {attribute: currattr}, desc)
                else:
                    print attribute
                    print repr(currattr)
                    raise Exception("BUGGY ATTRIBUTE FOR NODE")


def update(nodes, element, configmanager, inputdata):
    if nodes is not None:
        return update_nodes(nodes, element, configmanager, inputdata)
    elif element[0] == 'groups':
        return update_nodegroup(
            element[1], element[3], configmanager, inputdata)
    raise Exception("This line should never be reached")


def update_nodegroup(group, element, configmanager, inputdata):
    try:
        clearattribs = []
        for attrib in inputdata.attribs.iterkeys():
            if inputdata.attribs[attrib] is None:
                clearattribs.append(attrib)
        for attrib in clearattribs:
            del inputdata.attribs[attrib]
        if clearattribs:
            configmanager.clear_group_attributes(group, clearattribs)
        configmanager.set_group_attributes({group: inputdata.attribs})
    except ValueError as e:
        raise exc.InvalidArgumentException(str(e))
    return retrieve_nodegroup(group, element, configmanager, inputdata)


def update_nodes(nodes, element, configmanager, inputdata):
    updatedict = {}
    for node in nodes:
        updatenode = inputdata.get_attributes(node)
        clearattribs = []
        if updatenode:
            for attrib in updatenode.iterkeys():
                if updatenode[attrib] is None:
                    clearattribs.append(attrib)
            if len(clearattribs) > 0:
                for attrib in clearattribs:
                    del updatenode[attrib]
                configmanager.clear_node_attributes([node], clearattribs)
            updatedict[node] = updatenode
    try:
        configmanager.set_node_attributes(updatedict)
    except ValueError as e:
        raise exc.InvalidArgumentException(str(e))
    return retrieve(nodes, element, configmanager, inputdata)
