import confluent.selfservice as selfservice
import confluent.messages as msg
import confluent.runansible as runansible

_user_initiated_runs = {}
def update(nodes, element, configmanager, inputdata):
    if element[-1] != 'run':
        raise ValueError('Invalid element for remoteconfig plugin')
    for node in nodes:
        category = inputdata.inputbynode[node]
        playlist = selfservice.list_ansible_scripts(configmanager, node, category)
        if playlist:
            _user_initiated_runs[node] = True
            runansible.run_playbooks(playlist, [node])
            yield msg.CreatedResource(
                    '/nodes/{0}/deployment/remote_config/active/{0}'.format(node))
        else:
            yield msg.ConfluentNodeError('No remote configuration for category "{0}"', node)

def retrieve(nodes, element, configmanager, inputdata):
    for node in nodes:
        if element[-1] == 'active':
            rst = runansible.running_status.get(node, None)
            if not rst:
                return
            yield msg.ChildCollection(node)
        elif element[-2] == 'active' and element[-1] == node:
            rst = runansible.running_status.get(node, None)
            if not rst:
                return
            playstatus = rst.dump_dict()
            if playstatus['complete'] and _user_initiated_runs.get(node, False):
                del runansible.running_status[node]
                del _user_initiated_runs[node]
            yield msg.KeyValueData(playstatus, node)



