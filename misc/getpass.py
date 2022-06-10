import confluent.config.configmanager as cfm
import sys
c = cfm.ConfigManager(None)
cfg = c.get_node_attributes(sys.argv[1], 'secret.*', decrypt=True)
for node in cfg:
    for attr in cfg[node]:
        val = cfg[node][attr]['value']
        if not isinstance(val, str):
            val = val.decode('utf8')
        print('{}: {}'.format(attr, val))
