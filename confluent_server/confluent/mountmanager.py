
import asyncio
import eventlet
import confluent.messages as msg
import confluent.exceptions as exc
import struct
import socket
import os
mountsbyuser = {}
_browserfsd = None

async def assure_browserfs():
    global _browserfsd
    if _browserfsd is None:
        os.makedirs('/var/run/confluent/browserfs/mount', exist_ok=True)
        _browserfsd = await asyncio.subprocess.create_subprocess_exec(
            '/opt/confluent/bin/browserfs',
             '-c', '/var/run/confluent/browserfs/control',
             '-s', '127.0.0.1:4006',
             # browserfs supports unix domain websocket, however apache reverse proxy is dicey that way in some versions
             '-w', '/var/run/confluent/browserfs/mount')
        while not os.path.exists('/var/run/confluent/browserfs/control'):
            await asyncio.sleep(0.5)


async def handle_request(configmanager, inputdata, pathcomponents, operation):
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
            currmount = await requestmount(curruser, inputdata['name'])
            currmount['index'] = curridx
            if curruser not in mountsbyuser:
                mountsbyuser[curruser] = []
            mountsbyuser[curruser].append(currmount)
            yield msg.KeyValueData({
                'path': currmount['path'],
                'fullpath': '/var/run/confluent/browserfs/mount/{}'.format(currmount['path']),
                'authtoken': currmount['authtoken']
            })

async def requestmount(subdir, filename):
    await assure_browserfs()
    cloop = asyncio.get_event_loop()
    a = socket.socket(socket.AF_UNIX)
    a.settimeout(0)
    await cloop.sock_connect(a, '/var/run/confluent/browserfs/control')
    subname = subdir.encode()
    fname = filename.encode()
    await cloop.sock_sendall(a, struct.pack('!II', 1, len(subname)) + subname + struct.pack('!I', len(fname)) + fname)
    rsp = await cloop.sock_recv(a, 4)
    retcode = struct.unpack('!I', rsp)[0]
    if retcode != 0:
        raise Exception("Bad return code")
    rsp = await cloop.sock_recv(a, 4)
    nlen = struct.unpack('!I', rsp)[0]
    idstr = (await cloop.sock_recv(a, nlen)).decode('utf8')
    rsp = await cloop.sock_recv(a, 4)
    nlen = struct.unpack('!I', rsp)[0]
    authtok = (await cloop.sock_recv(a, nlen)).decode('utf8')
    thismount = {
            'id': idstr,
            'path': '{}/{}/{}'.format(idstr, subdir, filename),
            'authtoken': authtok
        }
    return thismount

