import confluent.messages as msg
import confluent.config.attributes as allattributes

def retrieve(nodes, element, configmanager, inputdata):
    attributes = configmanager.get_node_attributes(nodes)
    if element.endswith('/all'):
        for node in nodes:
            for attribute in sorted(allattributes.node.iterkeys()):
                if attribute in attributes[node]: #have a setting for it
                    val = attributes[node][attribute]
                else: # no setting, provide a blank
                    val = {'value': '', 'cryptvalue': ''}
                if attribute.startswith('secret.'):
                    yield msg.CryptedAttributes(node,
                        {attribute: val})
                else:
                    yield msg.Attributes(node,
                        {attribute: val['value']})
    elif element.endswith('/current'):
        for node in attributes.iterkeys():
            for attribute in sorted(attributes[node].iterkeys()):
                currattr = attributes[node][attribute]
                if 'value' in currattr:
                    yield msg.Attributes(node,
                        {attribute: currattr['value']})
                elif 'cryptvalue' in currattr:
                    yield msg.CryptedAttributes(node,
                        {attribute: currattr['cryptvalue']})
                else:
                    print repr(currattr)
                    raise Exception("BUGGY ATTRIBUTE FOR NODE")


def update(nodes, element, configmanager, inputdata):
    updatedict = {}
    for node in nodes:
        updatenode = inputdata.get_attributes(node)
        if updatenode:
            updatedict[node] = updatenode
    configmanager.set_node_attributes(updatedict)
