import confluent.exceptions as exc
import confluent.messages as msg
import confluent.config.attributes as allattributes

def retrieve(nodes, element, configmanager, inputdata):
    attributes = configmanager.get_node_attributes(nodes)
    if element[-1] == 'all':
        for node in nodes:
            for attribute in sorted(allattributes.node.iterkeys()):
                if attribute in attributes[node]: #have a setting for it
                    val = attributes[node][attribute]
                elif attribute == 'groups': # no setting, provide a blank
                    val = []
                else: # no setting, provide a blank
                    val = {'value': None}
                if attribute.startswith('secret.'):
                    yield msg.CryptedAttributes(node,
                        {attribute: val},
                        allattributes.node[attribute]['description'])
                elif isinstance(val, list):
                    yield msg.ListAttributes(node,
                        {attribute: val},
                        allattributes.node[attribute]['description'])
                else:
                    yield msg.Attributes(node,
                        {attribute: val['value']},
                        allattributes.node[attribute]['description'])
    elif element[-1] == 'current':
        for node in attributes.iterkeys():
            for attribute in sorted(attributes[node].iterkeys()):
                currattr = attributes[node][attribute]
                if 'value' in currattr:
                    yield msg.Attributes(node,
                        {attribute: currattr['value']},
                        allattributes.node[attribute]['description'])
                elif 'cryptvalue' in currattr:
                    yield msg.CryptedAttributes(node,
                        {attribute: currattr},
                        allattributes.node[attribute]['description'])
                elif isinstance(currattr, list):
                    yield msg.ListAttributes(node,
                        {attribute: currattr},
                        allattributes.node[attribute]['description'])
                else:
                    print repr(currattr)
                    raise Exception("BUGGY ATTRIBUTE FOR NODE")


def update(nodes, element, configmanager, inputdata):
    updatedict = {}
    for node in nodes:
        updatenode = inputdata.get_attributes(node)
        if updatenode:
            updatedict[node] = updatenode
    try:
        configmanager.set_node_attributes(updatedict)
    except ValueError:
        raise exc.InvalidArgumentException()
    return retrieve(nodes, element, configmanager, inputdata)
