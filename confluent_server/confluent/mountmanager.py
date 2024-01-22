
import confluent.messages as msg
import confluent.exceptions as exc
import struct
import eventlet.green.socket as socket
mountsbyuser = {}

def handle_request(configmanager, inputdata, pathcomponents, operation):
    curruser = configmanager.current_user
    if len(pathcomponents) == 0:
        mounts = mountsbyuser.get(curruser, [])
        if operation == 'retrieve':
            for mount in mounts:
                yield msg.ChildCollection(mount['index'])
        elif operation == 'create':
            if 'name' not in inputdata:
                raise exc.InvalidArgumentException('Required parameter "name" is missing')
            usedidx = set([])
            for mount in mounts:
                usedidx.add(mount['index'])
            curridx = 1
            while curridx in usedidx:
                curridx += 1
            currmount = requestmount(curruser, inputdata['name'])
            currmount['index'] = curridx
            if curruser not in mountsbyuser:
                mountsbyuser[curruser] = []
            mountsbyuser[curruser].append(currmount)
            yield msg.KeyValueData({
                'path': currmount['path'],
                'authtoken': currmount['authtoken']
            })

def requestmount(subdir, filename):
    a = socket.socket(socket.AF_UNIX)
    a.connect('/var/run/confluent/browserfs/control')
    subname = subdir.encode()
    a.send(struct.pack('!II', 1, len(subname)))
    a.send(subname)
    fname = filename.encode()
    a.send(struct.pack('!I', len(fname)))
    a.send(fname)
    rsp = a.recv(4)
    retcode = struct.unpack('!I', rsp)[0]
    if retcode != 0:
        raise Exception("Bad return code")
    rsp = a.recv(4)
    nlen = struct.unpack('!I', rsp)[0]
    idstr = a.recv(nlen).decode('utf8')
    rsp = a.recv(4)
    nlen = struct.unpack('!I', rsp)[0]
    authtok = a.recv(nlen).decode('utf8')
    thismount = {
            'id': idstr,
            'path': '{}/{}/{}'.format(idstr, subdir, filename),
            'authtoken': authtok
        }
    return thismount
