
import confluent.auth as auth
import eventlet
import confluent.messages as msg
import confluent.exceptions as exc
import confluent.util as util
import confluent.config.configmanager as configmanager
import struct
import eventlet.green.socket as socket
import eventlet.green.subprocess as subprocess
import base64
import os
import pwd
import confluent.httpapi as httpapi
mountsbyuser = {}
_vinzfd = None
_vinztoken = None
webclient = eventlet.import_patched('pyghmi.util.webclient')
startingup = False

# Handle the vinz VNC session
def assure_vinz():
    global _vinzfd
    global _vinztoken
    global startingup
    while startingup:
        eventlet.sleep(0.5)
    try:
        startingup = True
        if _vinzfd is None:
            _vinztoken = base64.b64encode(os.urandom(33), altchars=b'_-').decode()
            os.environ['VINZ_TOKEN'] = _vinztoken
            os.makedirs('/var/run/confluent/vinz/sessions', exist_ok=True)

            _vinzfd = subprocess.Popen(
                ['/opt/confluent/bin/vinz',
                '-c', '/var/run/confluent/vinz/control',
                '-w', '127.0.0.1:4007',
                '-a', '/var/run/confluent/vinz/approval',
                # vinz supports unix domain websocket, however apache reverse proxy is dicey that way in some versions
                '-d', '/var/run/confluent/vinz/sessions'])
            while not os.path.exists('/var/run/confluent/vinz/control'):
                eventlet.sleep(0.5)
            eventlet.spawn(monitor_requests)
    finally:
        startingup = False

_unix_by_nodename = {}
def get_url(nodename, inputdata):
    method = inputdata.inputbynode[nodename]
    assure_vinz()
    if method == 'wss':
        return f'/vinz/kvmsession/{nodename}'
    elif method == 'unix':
        if nodename not in _unix_by_nodename or not os.path.exists(_unix_by_nodename[nodename]):
            _unix_by_nodename[nodename] = request_session(nodename)
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


def send_grant(conn, nodename):
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
        wc = webclient.SecureHTTPConnection(bmc, 443, verifycallback=kv)
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
        conn.send(struct.pack('!BI', 1, len(bmc)))
        conn.send(bmc.encode())
        conn.send(struct.pack('!I', len(sessionid)))
        conn.send(sessionid.encode())
        conn.send(struct.pack('!I', len(sessiontok)))
        conn.send(sessiontok.encode())
        conn.send(struct.pack('!I', len(fprint)))
        conn.send(fprint)
        conn.send(struct.pack('!I', len(url)))
        conn.send(url.encode())
        conn.send(b'\xff')

def evaluate_request(conn):
    allow = False
    authname = None
    try:
        creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                struct.calcsize('iII'))
        pid, uid, gid = struct.unpack('iII', creds)
        if uid != os.getuid():
            return
        rqcode, fieldlen = struct.unpack('!BI', conn.recv(5))
        authtoken = conn.recv(fieldlen).decode()
        if authtoken != _vinztoken:
            return
        if rqcode == 2:  # disconnect notification
            fieldlen = struct.unpack('!I', conn.recv(4))[0]
            sessionid = conn.recv(fieldlen).decode()
            close_session(sessionid)
            conn.recv(1)  # digest 0xff
        if rqcode == 1:  # request for new connection
            fieldlen = struct.unpack('!I', conn.recv(4))[0]
            nodename = conn.recv(fieldlen).decode()
            idtype = struct.unpack('!B', conn.recv(1))[0]
            if idtype == 1:
                usernum = struct.unpack('!I', conn.recv(4))[0]
                if usernum == 0:  # root is a special guy
                    send_grant(conn, nodename)
                    return
                try:
                    authname = pwd.getpwuid(usernum).pw_name
                except Exception:
                    return
            elif idtype == 2:
                fieldlen = struct.unpack('!I', conn.recv(4))[0]
                sessionid = conn.recv(fieldlen)
                fieldlen = struct.unpack('!I', conn.recv(4))[0]
                sessiontok = conn.recv(fieldlen)
                try:
                    authname = httpapi.get_user_for_session(sessionid, sessiontok)
                except Exception:
                    return
            else:
                return
            conn.recv(1)  # should be 0xff
            if authname:
                allow = auth.authorize(authname, f'/nodes/{nodename}/console/ikvm')
            if allow:
                send_grant(conn, nodename)
    finally:
        conn.close()

def monitor_requests():
    a = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        os.remove('/var/run/confluent/vinz/approval')
    except Exception:
        pass
    a.bind('/var/run/confluent/vinz/approval')
    os.chmod('/var/run/confluent/vinz/approval', 0o600)
    a.listen(8)
    while True:
        conn, addr = a.accept()
        eventlet.spawn_n(evaluate_request, conn)

def request_session(nodename):
    assure_vinz()
    a = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    a.connect('/var/run/confluent/vinz/control')
    nodename = nodename.encode()
    a.send(struct.pack('!BI', 1, len(nodename)))
    a.send(nodename)
    a.send(b'\xff')
    rsp = a.recv(1)
    retcode = struct.unpack('!B', rsp)[0]
    if retcode != 1:
        raise Exception("Bad return code")
    rsp = a.recv(4)
    nlen = struct.unpack('!I', rsp)[0]
    sockname = a.recv(nlen).decode('utf8')
    retcode = a.recv(1)
    if retcode != b'\xff':
        raise Exception("Unrecognized response")
    return os.path.join('/var/run/confluent/vinz/sessions', sockname)

