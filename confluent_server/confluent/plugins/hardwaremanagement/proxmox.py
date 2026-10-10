
import asyncio
import base64
import codecs
import confluent.exceptions as exc
import confluent.vinzmanager as vinzmanager
import confluent.util as util
import confluent.messages as msg
import confluent.tasks as tasks
import aiohmi.util.webclient as webclient
import aiohmi.exceptions as pygexc
import confluent.interface.console as conapi
import confluent.log as log
import random
import io
import json
import re
import urllib.parse as urlparse
import aiohttp

def pve_error(body, status):
    # Non-2xx bodies arrive as raw bytes: JSON with 'message' and per-field 'errors'.
    if isinstance(body, bytes):
        try:
            body = json.loads(body)
        except ValueError:
            body = body.decode('utf8', 'replace')
    if isinstance(body, dict):
        message = (body.get('message') or '').strip()
        errors = body.get('errors')
        if isinstance(errors, dict):
            message = '{} ({})'.format(message, ', '.join(
                '{}: {}'.format(k, str(v).strip()) for k, v in errors.items()))
        body = message
    body = str(body or '').strip()
    return 'HTTP {}{}'.format(status, ': ' + body[:200] if body else '')


def next_config(pending):
    """Config as of the next start, from a /pending listing."""
    cfg = {}
    for datum in pending:
        if datum.get('delete'):
            continue
        if 'pending' in datum:
            cfg[datum['key']] = datum['pending']
        elif 'value' in datum:
            cfg[datum['key']] = datum['value']
    return cfg


# PVE's resolve_first_disk order.
_DRIVEBUSES = ('ide', 'scsi', 'virtio', 'sata')


def _devkey(dev):
    bus, num = re.match(r'([a-z]+)(\d+)$', dev).groups()
    busrank = _DRIVEBUSES.index(bus) if bus in _DRIVEBUSES else len(_DRIVEBUSES)
    return busrank, bus, int(num)


# confluent boot device -> device class moved to the front; None: disks first, network last.
BOOTCLASS = {'network': 'net', 'net': 'net', 'hd': 'disk', 'cd': 'cdrom', 'usb': 'usb', 'default': None}
# misc/proxmox/confluent-boot-oneshot.pl; makes a boot device one-time.
ONESHOT_HOOK = 'confluent-boot-oneshot.pl'
ONESHOT_MARKER = re.compile(r'^confluent-boot-restore: .*(?:\n|$)', re.M)


def device_class(dev, cfg):
    """net, usb, cdrom or disk, for a device named in a boot order."""
    if re.match(r'net\d+$', dev):
        return 'net'
    if re.match(r'usb\d+$', dev):
        # PVE ignores SPICE USB ports in the boot order.
        return None if (cfg.get(dev) or '').startswith('spice') else 'usb'
    if re.match(r'({})\d+$'.format('|'.join(_DRIVEBUSES)), dev):
        return 'cdrom' if 'media=cdrom' in (cfg.get(dev) or '') else 'disk'
    return None


def boot_devices(cfg):
    """Boot order as a device list: 'order=a;b' or legacy letters (default 'cdn').

    c: bootdisk or first disk, d: first CD-ROM, n: every NIC.
    """
    legacy = 'cdn'
    for item in (cfg.get('boot') or '').split(','):
        key, sep, val = item.partition('=')
        if key == 'order' and sep:
            return [dev for dev in val.split(';') if dev]
        if key == 'legacy' and sep:
            legacy = val
        elif key and not sep:
            legacy = key
    drives = sorted((key for key in cfg if re.match(r'({})\d+$'.format('|'.join(_DRIVEBUSES)), key)),
                    key=_devkey)
    cdroms = [key for key in drives if 'media=cdrom' in cfg[key]]
    disks = [key for key in drives if key not in cdroms]
    nets = sorted((key for key in cfg if re.match(r'net\d+$', key)), key=_devkey)
    devices = []
    for letter in legacy:
        if letter == 'c':
            bootdisk = cfg.get('bootdisk') if cfg.get('bootdisk') in disks else None
            if bootdisk or disks:
                devices.append(bootdisk or disks[0])
        elif letter == 'd' and cdroms:
            devices.append(cdroms[0])
        elif letter == 'n':
            devices.extend(nets)
    return devices


_SMBIOSFIELDS = (
    ('uuid', 'UUID'),
    ('manufacturer', 'Manufacturer'),
    ('product', 'Product name'),
    ('version', 'Version'),
    ('serial', 'Serial Number'),
    ('sku', 'SKU'),
    ('family', 'Family'),
)


def parse_smbios1(text):
    """smbios1 as a dict; with base64=1 every field but uuid is base64."""
    fields = {}
    for item in text.split(','):
        key, sep, val = item.partition('=')
        if sep:
            fields[key] = val
    if fields.get('base64') == '1':
        for key, val in fields.items():
            if key in ('uuid', 'base64'):
                continue
            try:
                fields[key] = base64.b64decode(val, validate=True).decode('utf8')
            except (ValueError, UnicodeDecodeError):
                pass
    return fields


# netN options; the remaining 'model=mac' pair is the NIC.
_NICOPTIONS = ('bridge', 'firewall', 'link_down', 'mtu', 'queues', 'rate', 'tag', 'trunks')


def parse_nic(text):
    """(model, mac) from a netN value: 'virtio=BC:24:..,bridge=vmbr0'."""
    model = mac = None
    for item in text.split(','):
        key, sep, val = item.partition('=')
        if key == 'model':
            model = val
        elif key == 'macaddr':
            mac = val
        elif sep and key not in _NICOPTIONS and model is None:
            model, mac = key, val
    return model, mac


class TaskFailed(Exception):
    """A PVE task ended with an error."""


class CustomVerifier(aiohttp.Fingerprint):
    def __init__(self, verifycallback):
        self._certverify = verifycallback

    def check(self, transport):
        sslobj = transport.get_extra_info("ssl_object")
        cert = sslobj.getpeercert(binary_form=True)
        if not self._certverify(cert):
            transport.close()
            raise pygexc.UnrecognizedCertificate('Unknown certificate',
                                                 cert)


class RetainedIO(io.BytesIO):
    # Need to retain buffer after close
    def __init__(self):
        self.resultbuffer = None
    def close(self):
        self.resultbuffer = self.getbuffer()
        super().close()

class KvmConnection:
    def __init__(self, consdata):
        #self.ws = WrappedWebSocket(host=bmc)
        #self.ws.set_verify_callback(kv)
        ticket = consdata['ticket']
        #user = consdata['user']
        port = consdata['port']
        urlticket = urlparse.quote(ticket)
        host = consdata['host']
        guest = consdata['guest']
        pac = consdata['pac']  # fortunately, we terminate this on our end, but it does kind of reduce the value of the
        # 'ticket' approach, as the general cookie must be provided as cookie along with the VNC ticket
        hosturl = host
        if ':' in hosturl:
            hosturl = '[' + hosturl + ']'
        self.url = f'/api2/json/nodes/{host}/{guest}/vncwebsocket?port={port}&vncticket={urlticket}'
        self.fprint = consdata['fprint']
        self.cookies = {
            'PVEAuthCookie': pac,
            }
        self.protos = ['binary']
        # The manager issued the ticket and owns the pinned fingerprint. It forwards the
        # websocket to the node running the guest, whose name may not resolve here.
        self.host = consdata['server']
        self.portnum = 8006
        self.password = consdata['ticket']


class KvmConnHandler:
    def __init__(self, pmxclient, node):
        self.pmxclient = pmxclient
        self.node = node

    async def connect(self):
        consdata = await self.pmxclient.get_vm_ikvm(self.node)
        consdata['fprint'] = self.pmxclient.fprint
        return KvmConnection(consdata)

class PmxConsole(conapi.Console):
    # termproxy drops idle sessions; xterm.js pings every 30s.
    keepalive_interval = 30

    def __init__(self, consdata, node, configmanager, apiclient):
        self.ws = None
        self.clisess = None
        self.consdata = consdata
        self.nodeconfig = configmanager
        self.connected = False
        self.bmc = consdata['server']
        self.node = node
        self.recvr = None
        self.keeper = None
        self.datacallback = None
        self.apiclient = apiclient
        # A UTF-8 character may span two writes.
        self.decoder = codecs.getincrementaldecoder('utf-8')('replace')

    async def lost(self):
        # Report the disconnect once.
        callback, self.datacallback = self.datacallback, None
        self.connected = False
        if callback:
            await callback(conapi.ConsoleEvent.Disconnect)

    async def recvdata(self):
        try:
            while self.connected:
                pendingdata = await self.ws.receive()
                if pendingdata.type == aiohttp.WSMsgType.BINARY:
                    await self.datacallback(pendingdata.data)
                elif pendingdata.type == aiohttp.WSMsgType.TEXT:
                    await self.datacallback(pendingdata.data.encode())
                elif pendingdata.type in (aiohttp.WSMsgType.PING, aiohttp.WSMsgType.PONG):
                    continue
                else:
                    # CLOSE, CLOSING, CLOSED or ERROR: session over.
                    await self.lost()
                    return
        except asyncio.CancelledError:
            pass

    async def keepalive(self):
        try:
            while self.connected:
                await asyncio.sleep(self.keepalive_interval)
                if self.connected:
                    await self.ws.send_str('2')
        except asyncio.CancelledError:
            pass
        except Exception:
            await self.lost()

    async def connect(self, callback):
        if await self.apiclient.get_vm_power(self.node) != 'on':
            await callback(conapi.ConsoleEvent.Disconnect)
            return
        # socket = new WebSocket(socketURL, 'binary'); - subprotocol binary
        # client handshake is:
        #     socket.send(PVE.UserName + ':' + ticket + "\n");

        # Peer sends 'OK' on handshake, other than that it's direct pass through
        # send '2' every 30 seconds for keepalive
        # data is xmitted with 0:<len>:data
        # resize is sent with 1:columns:rows:""
        self.datacallback = callback
        kv = util.TLSCertVerifier(
            self.nodeconfig, self.node, 'pubkeys.tls_hardwaremanager').verify_cert
        if ':' in self.bmc and not self.bmc.startswith('['):
            self.bmc = '[{0}]'.format(self.bmc)
        self.ssl = CustomVerifier(kv)
        ticket = self.consdata['ticket']
        user = self.consdata['user']
        port = self.consdata['port']
        urlticket = urlparse.quote(ticket)
        host = self.consdata['host']
        guest = self.consdata['guest']
        pac = self.consdata['pac']  # fortunately, we terminate this on our end, but it does kind of reduce the value of the
        # 'ticket' approach, as the general cookie must be provided as cookie along with the VNC ticket
        cookies = aiohttp.CookieJar(unsafe=True, quote_cookie=False)
        headers = {}
        if pac:
            cookies.update_cookies({'PVEAuthCookie': pac})
        if self.consdata.get('authorization'):
            headers['Authorization'] = self.consdata['authorization']
        self.clisess = aiohttp.ClientSession(cookie_jar=cookies)
        try:
            self.ws = await self.clisess.ws_connect(
                f'wss://{self.bmc}:8006/api2/json/nodes/{host}/{guest}/vncwebsocket?port={port}&vncticket={urlticket}',
                protocols=['binary'], ssl=self.ssl, headers=headers)
            await self.ws.send_str(f'{user}:{ticket}\n')
            data = await self.ws.receive()
            if data.data not in (b'OK', 'OK'):
                raise exc.TargetEndpointUnreachable(
                    'termproxy refused the session for {}: {!r}'.format(self.node, data.data))
            await self.ws.receive()  # swallow the 'starting serial terminal' message
        except Exception:
            await self.close()
            await callback(conapi.ConsoleEvent.Disconnect)
            return
        self.connected = True
        self.recvr = tasks.spawn_task(self.recvdata())
        self.keeper = tasks.spawn_task(self.keepalive())

    async def write(self, data):
        try:
            text = self.decoder.decode(data)
            if not text:
                return
            # Length in UTF-8 bytes, as xterm.js sends it.
            await self.ws.send_str('0:{}:{}'.format(len(text.encode('utf-8')), text))
        except Exception:
            await self.lost()

    async def close(self):
        if self.recvr:
            self.recvr.cancel()
            self.recvr = None
        if self.keeper:
            self.keeper.cancel()
            self.keeper = None
        if self.ws:
            await self.ws.close()
        if self.clisess:
            await self.clisess.close()
        self.connected = False
        self.datacallback = None

class PmxApiClient:
    def __init__(self, server, user, password, configmanager, node=None):
        self.user = user
        self.password = password
        self.pac = None
        pinnode, pinfield = server, 'pubkeys.tls'
        if configmanager and node is not None and \
                server not in configmanager.get_node_attributes(server, 'pubkeys.tls'):
            # Manager is not a confluent node: pin on the guest's node, as the console does.
            pinnode, pinfield = node, 'pubkeys.tls_hardwaremanager'
        if configmanager:
            cv = util.TLSCertVerifier(
                configmanager, pinnode, pinfield, subject=server
            ).verify_cert
        else:
            def cv(x):
                return True

        try:
            self.user = self.user.decode()
            self.password = self.password.decode()
        except Exception:
            pass
        self.server = server
        self.wc = webclient.WebConnection(server, port=8006, verifycallback=cv)
        self.fprint = None
        if configmanager:
            self.fprint = configmanager.get_node_attributes(pinnode, pinfield).get(pinnode, {}).get(pinfield, {}).get('value', None)
        self.vmmap = {}
        self.vmdupes = {}
        self.vmlist = {}
        self.vmbyid = {}
        self.logged = False

    @property
    def token(self):
        # 'user@realm!tokenid', secret as the password.
        return '!' in (self.user or '')

    async def login(self):
        if self.token:
            # Stateless: no ticket or CSRF token; a bad token is a 401 on first use.
            self.wc.set_header('Authorization', 'PVEAPIToken={}={}'.format(self.user, self.password))
            self.logged = True
            return
        loginform = {
                'username': self.user,
                'password': self.password,
            }
        loginbody = urlparse.urlencode(loginform)
        try:
            body, status = await self.wc.grab_json_response_with_status('/api2/json/access/ticket', loginbody, headers={'Content-Type': 'application/x-www-form-urlencoded'})
        except Exception:
            raise exc.TargetEndpointUnreachable("Unable to reach Proxmox server '{}'".format(self.server))
        if status == 401:
            raise exc.TargetEndpointBadCredentials("Bad credentials")
        data = body.get('data') if isinstance(body, dict) else None
        if status != 200 or not isinstance(data, dict) or 'ticket' not in data:
            raise exc.TargetEndpointUnreachable("Proxmox server '{}' refused login: {}".format(
                self.server, pve_error(body, status)))
        if data.get('NeedTFA'):
            raise exc.TargetEndpointBadCredentials(
                "Proxmox user '{}' requires two-factor authentication, which is not supported".format(self.user))
        self.pac = data['ticket']
        self.wc.cookies.update_cookies({'PVEAuthCookie': self.pac})
        self.wc.set_header('CSRFPreventionToken', data['CSRFPreventionToken'])
        self.logged = True

    # PVE waits ~10s for the config lock per attempt.
    lock_retries = 5
    lock_retry_delay = 2

    async def api(self, method, path, data=None, vm=None):
        """Call the PVE API; returns 'data'.

        With vm, path is relative to /nodes/<node>/qemu/<id>/. Retries once
        after a 401 (expired ticket) and once after a migration; writes that
        time out on the VM config lock are retried.
        """
        retried = set()
        lockwaits = 0
        lockstart = 0.0
        while True:
            if not self.logged:
                await self.login()
            url = path
            if vm is not None:
                host, guest = await self.get_vm(vm)
                url = f'/api2/json/nodes/{host}/{guest}/{path}'
            try:
                body, status = await self.wc.grab_json_response_with_status(url, data, method=method)
            except Exception:
                raise exc.TargetEndpointUnreachable("Unable to reach Proxmox server '{}'".format(self.server))
            if 200 <= status < 300:
                if lockwaits:
                    log.log({'info': '{}: waited {:.0f}s for the VM config lock'.format(
                        vm or url, asyncio.get_running_loop().time() - lockstart)})
                return body.get('data') if isinstance(body, dict) else body
            message = pve_error(body, status)
            if status == 401 and 'login' not in retried:
                retried.add('login')
                self.logged = False
                continue
            if vm is not None and 'does not exist' in message and 'map' not in retried:
                retried.add('map')
                self.vmmap.pop(vm, None)
                continue
            if method != 'GET' and "can't lock file" in message:
                # Another task on the VM holds its config lock.
                if not lockwaits:
                    lockstart = asyncio.get_running_loop().time()
                if lockwaits < self.lock_retries:
                    lockwaits += 1
                    await asyncio.sleep(self.lock_retry_delay)
                    continue
                raise exc.TargetResourceUnavailable(
                    'VM config locked by another Proxmox task; gave up after {} retries over {:.0f}s ({})'.format(
                        lockwaits, asyncio.get_running_loop().time() - lockstart, message))
            if status == 401:
                raise exc.TargetEndpointBadCredentials(message)
            raise exc.TargetResourceUnavailable(
                'Proxmox server {} {} {}: {}'.format(self.server, method, url, message))

    def get_screenshot(self, vm, outfile):
        raise Exception("Not implemented")

    async def map_vms(self):
        resources = await self.api('GET', '/api2/json/cluster/resources')
        # Names need not be unique; templates are skipped.
        byname = {}
        for datum in resources or []:
            if datum['type'] == 'qemu' and not datum.get('template'):
                byname.setdefault(datum.get('name'), []).append((datum['node'], datum['id']))
        self.vmmap = dict((name, vms[0]) for name, vms in byname.items() if len(vms) == 1)
        self.vmdupes = dict((name, [guest for _, guest in vms]) for name, vms in byname.items() if len(vms) > 1)
        return self.vmmap


    async def get_vm(self, vm):
        if vm not in self.vmmap:
            await self.map_vms()
        if vm in self.vmdupes:
            raise exc.InvalidArgumentException(
                "VM name {} is used by more than one guest on Proxmox server {} ({}); "
                "rename all but one".format(vm, self.server, ', '.join(self.vmdupes[vm])))
        if vm not in self.vmmap:
            raise exc.NotFoundException("VM {} not found on Proxmox server {}".format(vm, self.server))
        return self.vmmap[vm]


    async def get_vm_inventory(self, vm):
        # Current config: pending NICs are not present yet.
        cfg = await self.api('GET', 'config', vm=vm)
        info = {
            'Product name': 'Proxmox qemu virtual machine',
            'Manufacturer': 'qemu',
            }
        smbios = parse_smbios1(cfg.get('smbios1', ''))
        for field, label in _SMBIOSFIELDS:
            if smbios.get(field):
                info[label] = smbios[field]
        invitems = [{'name': 'System', 'present': True, 'information': info}]
        for key in sorted((k for k in cfg if re.match(r'net\d+$', k)), key=_devkey):
            model, mac = parse_nic(cfg[key])
            invitems.append({
                'present': True,
                'name': 'Network adapter {}'.format(key),
                'information': {
                    'Type': 'Ethernet',
                    'Model': model,
                    'MAC Address 1': mac,
                    }
                })
        yield msg.KeyValueData({'inventory': invitems}, vm)


    async def get_vm_ikvm(self, vm):
        return await self.get_vm_consproxy(vm, 'vnc')

    async def get_vm_serial(self, vm):
        return await self.get_vm_consproxy(vm, 'term')

    async def get_vm_consproxy(self, vm, constype):
        powstate = await self.get_vm_power(vm)
        if powstate != 'on':
            await asyncio.sleep(1 + random.random())
        consdata = await self.api('POST', f'{constype}proxy', vm=vm)
        # vmmap is current after api().
        host, guest = await self.get_vm(vm)
        consdata['server'] = self.server
        consdata['host'] = host
        consdata['guest'] = guest
        consdata['pac'] = self.pac
        consdata['authorization'] = self.wc.stdheaders.get('Authorization')
        return consdata

    async def get_vm_bootdev(self, vm):
        """(nextdevice, bootmode, persistent)."""
        cfg = next_config(await self.api('GET', 'pending', vm=vm))
        devices = boot_devices(cfg)
        first = device_class(devices[0], cfg) if devices else None
        nextdev = {'net': 'network', 'cdrom': 'cd', 'usb': 'usb'}.get(first, 'default')
        bootmode = 'uefi' if cfg.get('bios') == 'ovmf' else 'bios'
        persistent = ONESHOT_MARKER.search(cfg.get('description') or '') is None
        return nextdev, bootmode, persistent


    async def get_vm_power(self, vm):
        rsp = await self.api('GET', 'status/current', vm=vm)
        # 'status' is whether the QEMU process exists: any live process is on.
        currstatus = rsp.get('status')
        if currstatus == 'running':
            return 'on'
        elif currstatus == 'stopped':
            return 'off'
        raise exc.TargetResourceUnavailable(
            'Unknown power status {!r} (qmpstatus {!r}) for {}'.format(currstatus, rsp.get('qmpstatus'), vm))

    # Seconds per action; shutdown waits on the guest's ACPI handling.
    power_timeout = {'start': 60, 'stop': 60, 'shutdown': 300}

    async def set_vm_power(self, vm, state):
        current = None
        if state == 'diag':
            raise exc.InvalidArgumentException('Proxmox VMs have no diagnostic interrupt')
        if state not in ('on', 'off', 'shutdown', 'boot', 'reset'):
            raise exc.InvalidArgumentException('Unsupported power state {}'.format(state))
        if state == 'boot':
            current = await self.get_vm_power(vm)
            action = 'reset' if current == 'on' else 'start'
        elif state == 'reset':
            action = 'reset'
        else:
            # IPMI semantics: on when on, off when off, is a no-op.
            target = 'on' if state == 'on' else 'off'
            if await self.get_vm_power(vm) == target:
                return target, None
            action = {'on': 'start', 'off': 'stop', 'shutdown': 'shutdown'}[state]
        if action == 'reset':
            # Pending boot order needs a cold start.
            cfg = await self.api('GET', 'pending', vm=vm)
            if any(datum['key'] == 'boot' and 'pending' in datum for datum in cfg):
                await self.set_vm_power(vm, 'off')
                await self.set_vm_power(vm, 'on')
            else:
                await self.api('POST', 'status/reset', vm=vm)
            return 'reset', current
        target = 'on' if action == 'start' else 'off'
        # Retry a task that lost the config lock race.
        for attempt in range(3):
            # PVE's own shutdown timeout is shorter.
            params = {'timeout': self.power_timeout['shutdown']} if action == 'shutdown' else None
            upid = await self.api('POST', f'status/{action}', params, vm=vm)
            try:
                return await self.wait_power(vm, target, self.power_timeout[action], upid), current
            except TaskFailed as e:
                if "can't lock file" not in str(e) or attempt == 2:
                    raise exc.TargetResourceUnavailable(str(e))
                await asyncio.sleep(2)

    async def wait_power(self, vm, target, timeout, upid=None):
        """Wait for the power state; fail early if the action's task fails."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            newstate = await self.get_vm_power(vm)
            if newstate == target:
                return newstate
            if upid:
                host, _ = await self.get_vm(vm)
                task = await self.api('GET', '/api2/json/nodes/{}/tasks/{}/status'.format(
                    host, urlparse.quote(upid, safe='')))
                if task.get('status') == 'stopped' and task.get('exitstatus') != 'OK':
                    raise TaskFailed('{}: PVE task {} failed: {}'.format(
                        vm, upid.split(':')[5] if upid.count(':') > 5 else 'action', task.get('exitstatus')))
            if loop.time() >= deadline:
                raise exc.TargetResourceUnavailable(
                    '{} did not reach power state {} within {} seconds'.format(vm, target, timeout))
            await asyncio.sleep(0.5)

    async def set_vm_bootdev(self, vm, bootdev, persistent=True, bootmode='unspecified'):
        """Set the next boot device; returns True if applied persistently.

        One-time is opt-in per VM through the confluent-boot-oneshot
        hookscript: the order to restore goes in the description and the
        hookscript restores it after the next start. It holds until a cold
        start. Without the hookscript the order is applied persistently, quietly.
        """
        if bootdev in ('setup', 'floppy', 'http'):
            raise exc.InvalidArgumentException(
                'Proxmox VMs have no {} boot target; use network, hd, cd, usb or default'.format(bootdev))
        if bootdev not in BOOTCLASS:
            raise exc.InvalidArgumentException('Requested boot device {} not supported'.format(bootdev))
        cfg = next_config(await self.api('GET', 'pending', vm=vm))
        current = await self.api('GET', 'config', vm=vm)
        # bootmode is advisory: never change firmware under an installed OS.
        # nodesetboot sends uefi unless -b; the reply reports the actual mode.
        devices = boot_devices(cfg)
        want = BOOTCLASS[bootdev]
        if want is None:
            # Disks first, network last (undoes cd and usb too); unlisted NICs appended.
            disks = [d for d in devices if device_class(d, cfg) == 'disk']
            middle = [d for d in devices if device_class(d, cfg) not in ('disk', 'net')]
            nets = [d for d in devices if device_class(d, cfg) == 'net'] or \
                sorted((k for k in cfg if device_class(k, cfg) == 'net'), key=_devkey)
            front, rest = disks + middle, nets
        else:
            front = [d for d in devices if device_class(d, cfg) == want]
            if not front:
                # Not yet in the order.
                front = sorted((k for k in cfg if device_class(k, cfg) == want), key=_devkey)
            if not front:
                raise exc.InvalidArgumentException('{} has no {} device to boot from'.format(vm, bootdev))
            rest = [d for d in devices if d not in front]
        # Only the chosen class moves.
        neworder = 'order=' + ';'.join(front + rest)
        description = current.get('description') or ''
        marker = ONESHOT_MARKER.search(description)
        oneshot = not persistent and ONESHOT_HOOK in (current.get('hookscript') or '')
        update = {}
        if oneshot:
            if not marker:
                # Keep the original order across repeated one-time requests.
                restore = cfg.get('boot') or 'none'
                update['description'] = (description.rstrip('\n') + '\n' if description else '') + \
                    'confluent-boot-restore: {}\n'.format(restore)
        elif marker:
            # Persistent supersedes a pending restore.
            update['description'] = ONESHOT_MARKER.sub('', description)
        if neworder != cfg.get('boot'):
            update['boot'] = neworder
        if update:
            await self.api('PUT', 'config', update, vm=vm)
        return not oneshot


async def prep_proxmox_clients(nodes, configmanager):
    cfginfo = configmanager.get_node_attributes(nodes, ['hardwaremanagement.manager', 'secret.hardwaremanagementuser', 'secret.hardwaremanagementpassword'], decrypt=True)
    clientsbypmx = {}
    clientsbynode = {}
    for node in nodes:
        cfg = cfginfo[node]
        currpmx = cfg['hardwaremanagement.manager']['value']
        if currpmx not in clientsbypmx:
            user = cfg.get('secret.hardwaremanagementuser', {}).get('value', None)
            passwd = cfg.get('secret.hardwaremanagementpassword', {}).get('value', None)
            clientsbypmx[currpmx] = PmxApiClient(currpmx, user, passwd, configmanager, node)
            try:
                await clientsbypmx[currpmx].login()
            except exc.TargetEndpointBadCredentials as e:
                clientsbypmx[currpmx] = e
            except exc.TargetEndpointUnreachable as e:
                clientsbypmx[currpmx] = e
        clientsbynode[node] = clientsbypmx[currpmx]
    return clientsbynode

async def retrieve(nodes, element, configmanager, inputdata):
    clientsbynode = await prep_proxmox_clients(nodes, configmanager)
    for node in nodes:
        currclient = clientsbynode[node]
        if isinstance(currclient, Exception):
            yield msg.ConfluentNodeError(node, str(currclient))
            continue
        try:
            await currclient.get_vm(node)
        except Exception as e:
            yield msg.ConfluentNodeError(node, str(e))
            continue
        if element == ['power', 'state']:
            yield msg.PowerState(node, await currclient.get_vm_power(node))
        elif element == ['boot', 'nextdevice']:
            nextdev, bootmode, persistent = await currclient.get_vm_bootdev(node)
            yield msg.BootDevice(node, nextdev, bootmode=bootmode, persistent=persistent)
        elif element[:2] == ['inventory', 'hardware'] and len(element) == 4:
            async for rsp in currclient.get_vm_inventory(node):
                yield rsp
        elif element == ['console', 'ikvm_methods']:
            dsc = {'ikvm_methods': ['vnc']}
            yield msg.KeyValueData(dsc, node)
        elif element == ['console', 'ikvm_screenshot']:
            # good background for the webui, and kitty
            yield msg.ConfluentNodeError(node, "vnc available, screenshot not available")
        elif element == ['health', 'hardware']:
            yield msg.HealthSummary('unknown', node)
            yield msg.SensorReadings([], node)

async def update(nodes, element, configmanager, inputdata):
    clientsbynode = await prep_proxmox_clients(nodes, configmanager)
    for node in nodes:
        currclient = clientsbynode[node]
        if isinstance(currclient, Exception):
            yield msg.ConfluentNodeError(node, str(currclient))
            continue
        try:
            await currclient.get_vm(node)
        except Exception as e:
            yield msg.ConfluentNodeError(node, str(e))
            continue
        if element == ['power', 'state']:
            # One failing guest must not abort the rest.
            try:
                newstate, oldstate = await currclient.set_vm_power(node, inputdata.powerstate(node))
            except exc.ConfluentException as e:
                yield msg.ConfluentNodeError(node, str(e))
                continue
            yield  msg.PowerState(node, newstate, oldstate)
        elif element == ['boot', 'nextdevice']:
            try:
                applied_persistent = await currclient.set_vm_bootdev(
                    node, inputdata.bootdevice(node), persistent=inputdata.persistent(node),
                    bootmode=inputdata.bootmode(node))
            except exc.ConfluentException as e:
                yield msg.ConfluentNodeError(node, str(e))
                continue
            nextdev, bootmode, _ = await currclient.get_vm_bootdev(node)
            # Persistent if one-time was requested without the hookscript.
            yield msg.BootDevice(node, nextdev, bootmode=bootmode, persistent=applied_persistent)
        elif element == ['console', 'ikvm']:
            currclient = clientsbynode[node]
            if currclient.token:
                # vinz forwards a cookie; a token needs a header.
                yield msg.ConfluentNodeError(node, 'VNC needs a Proxmox user with a password; '
                                                   'API tokens cannot be passed to the VNC proxy')
                return
            try:
                url = await vinzmanager.get_url(node, inputdata, nodeparmcallback=KvmConnHandler(currclient, node).connect)
            except Exception as e:
                print(repr(e))
                return
            yield msg.ChildCollection(url)
            return

# assume this is only console for now
async def create(nodes, element, configmanager, inputdata):
    clientsbynode = await prep_proxmox_clients(nodes, configmanager)
    for node in nodes:
        if isinstance(clientsbynode[node], Exception):
            yield msg.ConfluentNodeError(node, str(clientsbynode[node]))
            continue
        try:
            await clientsbynode[node].get_vm(node)
        except Exception as e:
            yield msg.ConfluentNodeError(node, str(e))
            continue
        if element == ['console', 'ikvm']:
            currclient = clientsbynode[node]
            if currclient.token:
                # vinz forwards a cookie; a token needs a header.
                yield msg.ConfluentNodeError(node, 'VNC needs a Proxmox user with a password; '
                                                   'API tokens cannot be passed to the VNC proxy')
                return
            try:
                url = await vinzmanager.get_url(node, inputdata, nodeparmcallback=KvmConnHandler(currclient, node).connect)
            except Exception as e:
                print(repr(e))
                return
            yield msg.ChildCollection(url)
            return
        serialdata = await clientsbynode[node].get_vm_serial(node)
        yield PmxConsole(serialdata, node, configmanager, clientsbynode[node])
        return


async def _selftest():
    import sys
    import os
    myuser = os.environ['PMXUSER']
    mypass = os.environ['PMXPASS']
    vc = PmxApiClient(sys.argv[1], myuser, mypass, None)
    vm = sys.argv[2]
    if sys.argv[3] == 'setboot':
        await vc.set_vm_bootdev(vm, sys.argv[4])
        await vc.get_vm_bootdev(vm)
    elif sys.argv[3] == 'power':
        await vc.set_vm_power(vm, sys.argv[4])
    elif sys.argv[3] == 'getinfo':
        print(repr([datum.kvpairs async for datum in vc.get_vm_inventory(vm)]))
        print("Bootdev: " + (await vc.get_vm_bootdev(vm))[0])
        print("Power: " + await vc.get_vm_power(vm))
        #print("Serial: " + repr(vc.get_vm_serial(vm)))


if __name__ == '__main__':
    asyncio.run(_selftest())
