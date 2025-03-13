# Copyright 2014 IBM Corporation
# Copyright 2017-2019 Lenovo
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

import ast
import confluent.exceptions as exc
import confluent.messages as msg
import confluent.config.attributes as allattributes
import confluent.config.configmanager as configmod
import confluent.util as util
from fnmatch import fnmatch


def retrieve(nodes, element, configmanager, inputdata, clearwarnbynode=None):
    configmanager.check_quorum()
    if nodes is not None:
        return retrieve_nodes(nodes, element, configmanager, inputdata, clearwarnbynode)
    elif element[0] == 'nodegroups':
        return retrieve_nodegroup(
            element[1], element[3], configmanager, inputdata, clearwarnbynode)


def retrieve_nodegroup(nodegroup, element, configmanager, inputdata, clearwarnbynode=None):
    try:
        grpcfg = configmanager.get_nodegroup_attributes(nodegroup)
    except KeyError:
        if not configmanager.is_nodegroup(nodegroup):
            raise exc.NotFoundException(
                'Invalid nodegroup: {0} not found'.format(nodegroup))
        raise
    if element == 'all':
        theattrs = set(allattributes.node).union(set(grpcfg))
        theattrs.add('nodes')
        theattrs.add('noderange')
        for attribute in sorted(theattrs):
            if attribute == 'groups':
                continue
            if attribute == 'nodes':
                yield msg.ListAttributes(
                    kv={'nodes': list(grpcfg.get('nodes', []))},
                    desc="The nodes belonging to this group")
                continue
            if attribute in grpcfg:
                val = grpcfg[attribute]
            else:
                val = {'value': None}
            if attribute == 'noderange':
                val['desc'] = 'The noderange this group is expanded ' \
                    'to when used in noderange, exclusive with static ' \
                    'nodes'
            if attribute.startswith('secret.') or attribute.startswith('crypted.') or attribute.startswith('custom.nodesecret.'):
                yield msg.CryptedAttributes(
                    kv={attribute: val},
                    desc=allattributes.node[attribute]['description'])
            elif isinstance(val, list):
                yield msg.ListAttributes(
                    kv={attribute: val},
                    desc=allattributes.node.get(
                        attribute, {}).get('description', ''))
            else:
                yield msg.Attributes(
                    kv={attribute: val},
                    desc=allattributes.node.get(attribute, {}).get(
                        'description', ''))
    if element == 'current':
        for attribute in sorted(list(grpcfg)):
            currattr = grpcfg[attribute]
            if attribute == 'nodes':
                if not currattr:
                    continue
                desc = 'The nodes belonging to this group'
            elif attribute == 'noderange':
                desc = 'A dynamic noderange that this group refers to in noderange expansion'
            else:
                try:
                    desc = allattributes.node[attribute]['description']
                except KeyError:
                    desc = ''
            if 'value' in currattr or 'expression' in currattr:
                yield msg.Attributes(kv={attribute: currattr}, desc=desc)
            elif 'cryptvalue' in currattr or 'hashvalue' in currattr:
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
            elif currattr:
                print(attribute)
                print(repr(currattr))
                raise Exception("BUGGY ATTRIBUTE FOR NODEGROUP")


def retrieve_nodes(nodes, element, configmanager, inputdata, clearwarnbynode):
    attributes = configmanager.get_node_attributes(nodes)
    if element[-1] == 'all':
        for node in util.natural_sort(nodes):
            if clearwarnbynode and node in clearwarnbynode:
                yield msg.Attributes(node, {'_warnings': clearwarnbynode[node]})
            theattrs = set(allattributes.node).union(set(attributes[node]))
            for attribute in sorted(theattrs):
                if attribute in attributes[node]:  # have a setting for it
                    val = attributes[node][attribute]
                elif attribute == 'groups':  # no setting, provide a blank
                    val = []
                else:  # no setting, provide a blank
                    val = {'value': None}
                if attribute.startswith('secret.') or attribute.startswith('crypted.') or attribute.startswith('custom.nodesecret.'):
                    yield msg.CryptedAttributes(
                        node, {attribute: val},
                        allattributes.node.get(
                            attribute, {}).get('description', ''))
                elif isinstance(val, list):
                    yield msg.ListAttributes(
                        node, {attribute: val},
                        allattributes.node.get(
                            attribute, {}).get('description', ''))
                else:
                    yield msg.Attributes(
                        node, {attribute: val},
                        allattributes.node.get(
                            attribute, {}).get('description', ''))
    elif element[-1] == 'current':
        for node in util.natural_sort(list(attributes)):
            for attribute in sorted(attributes[node]):
                currattr = attributes[node][attribute]
                try:
                    desc = allattributes.node[attribute]['description']
                except KeyError:
                    desc = ''
                if 'value' in currattr or 'expression' in currattr:
                    yield msg.Attributes(node, {attribute: currattr}, desc)
                elif 'cryptvalue' in currattr or 'hashvalue' in currattr:
                    yield msg.CryptedAttributes(
                        node, {attribute: currattr}, desc)
                elif isinstance(currattr, list):
                    yield msg.ListAttributes(
                        node, {attribute: currattr}, desc)
                elif currattr:
                    print(attribute)
                    print(repr(currattr))
                    raise Exception("BUGGY ATTRIBUTE FOR NODE")


def update(nodes, element, configmanager, inputdata):
    if nodes is not None:
        return update_nodes(nodes, element, configmanager, inputdata)
    elif element[0] == 'nodegroups':
        return update_nodegroup(
            element[1], element[3], configmanager, inputdata)
    raise Exception("This line should never be reached")


def update_nodegroup(group, element, configmanager, inputdata):
    if element == 'check':
        check = inputdata.attribs
        decrypt = configmanager.decrypt
        configmanager.decrypt = True
        currinfo = configmanager.get_nodegroup_attributes(group, list(check))
        configmanager.decrypt = decrypt
        for inf in check:
            checkvalue = check[inf]
            if isinstance(checkvalue, dict):
                checkvalue = checkvalue.get('value', None)
            currvalue = currinfo.get(inf, {}).get('value')
            if checkvalue == currvalue:
                raise exc.InvalidArgumentException('Checked value matches existing value')
        return retrieve_nodegroup(group, element, configmanager, inputdata)
    if 'rename' in element:
        namemap = {}
        namemap[group] = inputdata.attribs['rename']
        configmanager.rename_nodegroups(namemap)
        return yield_rename_resources(namemap, isnode=False)
    try:
        clearattribs = []
        for attrib in inputdata.attribs:
            if inputdata.attribs[attrib] is None:
                clearattribs.append(attrib)
            else:
                try:
                    ast.parse(attrib)
                except SyntaxError as e:
                    markup = (e.text[:e.offset-1] + '-->' + e.text[e.offset-1] + '<--' + e.text[e.offset:]).strip()
                    raise exc.InvalidArgumentException('Syntax error in attribute name: "{0}"'.format(markup))
        for attrib in clearattribs:
            del inputdata.attribs[attrib]
        if clearattribs:
            configmanager.clear_group_attributes(group, clearattribs)
        configmanager.set_group_attributes({group: inputdata.attribs})
    except ValueError as e:
        raise exc.InvalidArgumentException(str(e))
    return retrieve_nodegroup(group, element, configmanager, inputdata)


def _expand_expression(nodes, configmanager, inputdata):
    expression = inputdata.get_attributes(list(nodes)[0])
    if type(expression) is dict:
        expression = expression['expression']
    if type(expression) is dict:
        expression = expression['expression']
    pernodeexpressions = {}
    try:
        for expanded in configmanager.expand_attrib_expression(nodes,
                                                               expression):
            pernodeexpressions[expanded[0]] = expanded[1]
        for node in util.natural_sort(pernodeexpressions):
            yield msg.KeyValueData({'value': pernodeexpressions[node]}, node)
    except SyntaxError as e:
        markup = (e.text[:e.offset-1] + '-->' + e.text[e.offset-1] + '<--' + e.text[e.offset:]).strip()
        raise exc.InvalidArgumentException(
            'Bad confluent expression syntax (must use "{{" and "}}" if not '
            'desiring confluent expansion): ' + markup)
    except ValueError as e:
        raise exc.InvalidArgumentException(
            'Bad confluent expression syntax (must use "{{" and "}}" if not '
            'desiring confluent expansion): ' + str(e))



def create(nodes, element, configmanager, inputdata):
    if nodes is not None and element[-1] == 'expression':
        return _expand_expression(nodes, configmanager, inputdata)

def yield_rename_resources(namemap, isnode):
    for node in namemap:
        if isnode:
            yield msg.RenamedNode(node, namemap[node])
        else:
            yield msg.RenamedResource(node, namemap[node])

def update_nodes(nodes, element, configmanager, inputdata):
    updatedict = {}
    if not nodes:
        raise exc.InvalidArgumentException(
            'No action to take, noderange is empty (if trying to define '
            'group attributes, use nodegroupattrib)')
    if element[-1] == 'check':
        for node in nodes:
            check = inputdata.get_attributes(node, allattributes.node)
            currinfo = configmanager.get_node_attributes(node, list(check), decrypt=True)
            for inf in check:
                checkvalue = check[inf]
                if isinstance(checkvalue, dict):
                    checkvalue = checkvalue.get('value', None)
                currvalue = currinfo.get(node, {}).get(inf, {}).get('value')
                if checkvalue == currvalue:
                    raise exc.InvalidArgumentException('Checked value matches existing value')
        return retrieve(nodes, element, configmanager, inputdata)
    if 'rename' in element:
        namemap = {}
        for node in nodes:
            rename = inputdata.get_attributes(node)
            namemap[node] = rename['rename']
        configmanager.rename_nodes(namemap)
        return yield_rename_resources(namemap, isnode=True)
    clearwarnbynode = {}
    for node in nodes:
        updatenode = inputdata.get_attributes(node, allattributes.node)
        clearattribs = []
        if updatenode:
            for attrib in list(updatenode):
                if updatenode[attrib] is None:
                    del updatenode[attrib]
                    if '*' in attrib:
                        currnodeattrs = configmanager.get_node_attributes(node, attrib)
                        for matchattrib in currnodeattrs.get(node, {}):
                            clearattribs.append(matchattrib)
                    elif attrib in allattributes.node  or attrib.startswith('custom.') or attrib.startswith('net.'):
                        clearattribs.append(attrib)
                    else:
                        foundattrib = False
                        for candattrib in configmod._attraliases:
                            if fnmatch(candattrib, attrib):
                                attrib = configmod._attraliases[candattrib]
                        for candattrib in allattributes.node:
                            if fnmatch(candattrib, attrib):
                                clearattribs.append(candattrib)
                                foundattrib = True
                        if not foundattrib:
                            raise exc.InvalidArgumentException("No attribute matches '" + attrib + "' (try wildcard if trying to clear a group)")
                elif '*' in attrib:
                    currnodeattrs = configmanager.get_node_attributes(node, attrib)
                    for matchattrib in currnodeattrs.get(node, {}):
                        updatenode[matchattrib] = updatenode[attrib]
                    del updatenode[attrib]
                else:
                    try:
                        ast.parse(attrib)
                    except SyntaxError as e:
                        markup = (e.text[:e.offset-1] + '-->' + e.text[e.offset-1] + '<--' + e.text[e.offset:]).strip()
                        raise exc.InvalidArgumentException('Syntax error in attribute name: "{0}"'.format(markup))
            if len(clearattribs) > 0:
                clearwarnbynode[node] = []
                configmanager.clear_node_attributes([node], clearattribs, warnings=clearwarnbynode[node])
            updatedict[node] = updatenode
    try:
        configmanager.set_node_attributes(updatedict)
    except ValueError as e:
        raise exc.InvalidArgumentException(str(e))
    return retrieve(nodes, element, configmanager, inputdata, clearwarnbynode)
