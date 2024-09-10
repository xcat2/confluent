
import asyncio
import confluent.auth as auth
import confluent.messages as msg
import confluent.exceptions as exc
import confluent.util as util
import confluent.config.configmanager as configmanager
import struct
import base64
import os
import pwd
import confluent.httpapi as httpapi
mountsbyuser = {}
_vinzfd = None
_vinztoken = None
import socket
import aiohmi.util.webclient as webclient


# Handle the vinz VNC session
async def assure_vinz():
    global _vinzfd
    global _vinztoken
    if _vinzfd is None:
        _vinztoken = base64.b64encode(os.urandom(33), altchars=b'_-').decode()
        os.environ['VINZ_TOKEN'] = _vinztoken
        os.makedirs('/var/run/confluent/vinz/sessions', exist_ok=True)

        _vinzfd = await asyncio.subprocess.create_subprocess_exec(
            '/opt/confluent/bin/vinz',
             '-c', '/var/run/confluent/vinz/control',
             '-w', '127.0.0.1:4007',
             '-a', '/var/run/confluent/vinz/approval',
             # vinz supports unix domain websocket, however apache reverse proxy is dicey that way in some versions
             '-d', '/var/run/confluent/vinz/sessions')
        while not os.path.exists('/var/run/confluent/vinz/control'):
            await asyncio.sleep(0.5)
        util.spawn(monitor_requests())

_unix_by_nodename = {}
async def get_url(nodename, inputdata):
    method = inputdata.inputbynode[nodename]
    assure_vinz()
    if method == 'wss':
        return f'/vinz/kvmsession/{nodename}'
    elif method == 'unix':
        if nodename not in _unix_by_nodename or not os.path.exists(_unix_by_nodename[nodename]):
            _unix_by_nodename[nodename] = await request_session(nodename)
        return _unix_by_nodename[nodename]


_usersessions = {}
def close_session(sessionid):
    sessioninfo = _usersessions.get(sessionid, None)
    if not sessioninfo:
        return
    del _usersessions[sessionid]
    nodename = sessioninfo['nodename']
    wc = sessioninfo['webclient']
    cfg = configmanager.ConfigManager(None)
    c = cfg.get_node_attributes(
        nodename,
        ['secret.hardwaremanagementuser',
         'secret.hardwaremanagementpassword',
        ], decrypt=True)
    bmcuser = c.get(nodename, {}).get(
        'secret.hardwaremanagementuser', {}).get('value', None)
    bmcpass = c.get(nodename, {}).get(
        'secret.hardwaremanagementpassword', {}).get('value', None)
    if not isinstance(bmcuser, str):
        bmcuser = bmcuser.decode()
    if not isinstance(bmcpass, str):
        bmcpass = bmcpass.decode()
    if bmcuser and bmcpass:
        wc.grab_json_response_with_status(
            '/logout', {'data': [bmcuser, bmcpass]},
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-XSRF-TOKEN': wc.cookies['XSRF-TOKEN']})


async def send_grant(conn, nodename):
    cloop = asyncio.get_event_loop()
    cfg = configmanager.ConfigManager(None)
    c = cfg.get_node_attributes(
        nodename,
        ['secret.hardwaremanagementuser',
         'secret.hardwaremanagementpassword',
         'hardwaremanagement.manager'], decrypt=True)
    bmcuser = c.get(nodename, {}).get(
        'secret.hardwaremanagementuser', {}).get('value', None)
    bmcpass = c.get(nodename, {}).get(
        'secret.hardwaremanagementpassword', {}).get('value', None)
    bmc = c.get(nodename, {}).get(
        'hardwaremanagement.manager', {}).get('value', None)
    if bmcuser and bmcpass and bmc:
        kv = util.TLSCertVerifier(cfg, nodename,
                                  'pubkeys.tls_hardwaremanager').verify_cert
        wc = webclient.WebConnection(bmc, 443, verifycallback=kv)
        if not isinstance(bmcuser, str):
            bmcuser = bmcuser.decode()
        if not isinstance(bmcpass, str):
            bmcpass = bmcpass.decode()
        rsp = wc.grab_json_response_with_status(
            '/login', {'data': [bmcuser, bmcpass]},
            headers={'Content-Type': 'application/json',
                     'Accept': 'application/json'})
        sessionid = wc.cookies['SESSION']
        sessiontok = wc.cookies['XSRF-TOKEN']
        _usersessions[sessionid] = {
            'webclient': wc,
            'nodename': nodename,
        }
        url = '/kvm/0'
        fprintinfo = cfg.get_node_attributes(nodename, 'pubkeys.tls_hardwaremanager')
        fprint = fprintinfo.get(
            nodename, {}).get('pubkeys.tls_hardwaremanager', {}).get('value', None)
        if not fprint:
            return
        fprint = fprint.split('$', 1)[1]
        fprint = bytes.fromhex(fprint)
        await cloop.sock_send(conn, struct.pack('!BI', 1, len(bmc)))
        await cloop.sock_send(conn, bmc.encode())
        await cloop.sock_send(conn, struct.pack('!I', len(sessionid)))
        await cloop.sock_send(conn, sessionid.encode())
        await cloop.sock_send(conn, struct.pack('!I', len(sessiontok)))
        await cloop.sock_send(conn, sessiontok.encode())
        await cloop.sock_send(conn, struct.pack('!I', len(fprint)))
        await cloop.sock_send(conn, fprint)
        await cloop.sock_send(conn, struct.pack('!I', len(url)))
        await cloop.sock_send(conn, url.encode())
        await cloop.sock_send(conn, b'\xff')

async def evaluate_request(conn):
    allow = False
    authname = None
    cloop = asyncio.get_event_loop()
    try:
        creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                struct.calcsize('iII'))
        pid, uid, gid = struct.unpack('iII', creds)
        if uid != os.getuid():
            return
        recvdata = await cloop.sock_recv(conn, 5)
        rqcode, fieldlen = struct.unpack('!BI', recvdata)
        authtoken = await cloop.sock_recv(conn, fieldlen)
        authtoken = authtoken.decode()
        if authtoken != _vinztoken:
            return
        if rqcode == 2:  # disconnect notification
            msglen = await cloop.sock_recv(4)
            fieldlen = struct.unpack('!I', msglen)[0]
            sessionid = (await cloop.sock_recv(conn, fieldlen)).decode()
            close_session(sessionid)
            await cloop.sock_recv(conn, 1)  # digest 0xff
        if rqcode == 1:  # request for new connection
            lenbytes = await cloop.sock_recv(conn, 4)
            fieldlen = struct.unpack('!I', lenbytes)[0]
            nodename = (await cloop.sock_recv(conn, fieldlen)).decode()
            idbyte = await cloop.sock_recv(conn, 1)
            idtype = struct.unpack('!B', idbyte)[0]
            if idtype == 1:
                msgbytes = cloop.sock_recv(conn, 4)
                usernum = struct.unpack('!I', msgbytes)[0]
                if usernum == 0:  # root is a special guy
                    await send_grant(conn, nodename)
                    return
                try:
                    authname = pwd.getpwuid(usernum).pw_name
                except Exception:
                    return
            elif idtype == 2:
                msgbytes = await cloop.sock_recv(conn, 4)
                fieldlen = struct.unpack('!I', msgbytes)[0]
                sessionid = cloop.sock_recv(conn, fieldlen)
                msgbytes = await cloop.sock_recv(conn, 4)
                fieldlen = struct.unpack('!I', msgbytes)[0]
                sessiontok = await cloop.sock_recv(conn, fieldlen)
                try:
                    authname = httpapi.get_user_for_session(sessionid, sessiontok)
                except Exception:
                    return
            else:
                return
            await cloop.sock_recv(conn, 1)  # should be 0xff
            if authname:
                allow = auth.authorize(authname, f'/nodes/{nodename}/console/ikvm')
            if allow:
                await send_grant(conn, nodename)
    finally:
        conn.close()

async def monitor_requests():
    cloop = asyncio.get_event_loop()
    a = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        os.remove('/var/run/confluent/vinz/approval')
    except Exception:
        pass
    a.bind('/var/run/confluent/vinz/approval')
    os.chmod('/var/run/confluent/vinz/approval', 0o600)
    a.listen(8)
    while True:
        conn, addr = await cloop.sock_accept(a)
        util.spawn(evaluate_request(conn))

async def request_session(nodename):
    assure_vinz()
    cloop = asyncio.get_event_loop()
    a = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    a.connect('/var/run/confluent/vinz/control')
    nodename = nodename.encode()
    await cloop.sock_send(a, struct.pack('!BI', 1, len(nodename)))
    await cloop.sock_send(a, nodename)
    await cloop.sock_send(a, b'\xff')
    rsp = await cloop.sock_recv(a, 1)
    retcode = struct.unpack('!B', rsp)[0]
    if retcode != 1:
        raise Exception("Bad return code")
    rsp = await cloop.sock_recv(a, 4)
    nlen = struct.unpack('!I', rsp)[0]
    sockname = await cloop.sock_recv(a, nlen).decode('utf8')
    retcode = await cloop.sock_recv(a, 1)
    if retcode != b'\xff':
        raise Exception("Unrecognized response")
    return os.path.join('/var/run/confluent/vinz/sessions', sockname)

