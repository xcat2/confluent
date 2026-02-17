import confluent.networking.srlinux as srlinux
import eventlet
import eventlet.queue as queue
import confluent.messages as msg
import traceback


def retrieve_node(node, element, user, pwd, configmanager, inputdata, results):
    try:
        retrieve_node_backend(node, element, user, pwd, configmanager, inputdata, results)
    except Exception as e:
        print(traceback.format_exc())
        print(repr(e))


def simplify_name(name):
    return name.lower().replace(' ', '_').replace('/', '-').replace(
        '_-_', '-')


def retrieve_node_backend(node, element, user, pwd, configmanager, inputdata, results):
    cli = srlinux.SRLinuxClient(node, user, pwd, configmanager)
    if element == ['power', 'state']:  # client initted successfully, must be on
        results.put(msg.PowerState(node, 'on'))
    elif element == ['health', 'hardware']:
        hinfo = cli.get_health()
        results.put(msg.HealthSummary(hinfo.get('health', 'unknown'), name=node))
        results.put(msg.SensorReadings(hinfo.get('sensors', []), name=node))
    elif element[:3] == ['inventory', 'hardware', 'all']:
        if len(element) == 3:
            results.put(msg.ChildCollection('all'))
            return
        invinfo = cli.get_inventory()
        if invinfo:
            results.put(msg.KeyValueData({'inventory': invinfo}, node))
    elif element[:3] == ['inventory', 'firmware', 'all']:
        if len(element) == 3:
            results.put(msg.ChildCollection('all'))
            return
        fwinfo = []
        for fwnam, fwdat in cli.get_firmware().items():
            fwinfo.append({fwnam: fwdat})
        if fwinfo:
            results.put(msg.Firmware(fwinfo, node))
    elif element == ['sensors', 'hardware', 'all']:
        sensors = cli.get_sensors()
        for sensor in sensors:
            results.put(msg.ChildCollection(simplify_name(sensor['name'])))
    elif element[:3] == ['sensors', 'hardware', 'all']:
        sensors = cli.get_sensors()
        for sensor in sensors:
            if element[-1] == 'all' or simplify_name(sensor['name']) == element[-1]:
                results.put(msg.SensorReadings([sensor], node))
    else:
        print(repr(element))


def retrieve(nodes, element, configmanager, inputdata):
    results = queue.LightQueue()
    workers = set([])
    creds = configmanager.get_node_attributes(
        nodes, ['secret.hardwaremanagementuser', 'secret.hardwaremanagementpassword'], decrypt=True)
    for node in nodes:
        cred = creds.get(node, {})
        user = cred.get('secret.hardwaremanagementuser', {}).get('value')
        pwd = cred.get('secret.hardwaremanagementpassword', {}).get('value')
        try:
            user = user.decode()
            pwd = pwd.decode()
        except Exception:
            pass
        if not user or not pwd:
            yield msg.ConfluentTargetInvalidCredentials(node)
            continue
        workers.add(eventlet.spawn(retrieve_node, node, element, user, pwd, configmanager, inputdata, results))
    while workers:
        try:
            datum = results.get(block=True, timeout=10)
            while datum:
                if datum:
                    yield datum
                datum = results.get_nowait()
        except queue.Empty:
            pass
        eventlet.sleep(0.001)
        for t in list(workers):
            if t.dead:
                workers.discard(t)
    try:
        while True:
            datum = results.get_nowait()
            if datum:
                yield datum
    except queue.Empty:
        pass
