# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 IBM Corporation
# Copyright 2017-2018 Lenovo
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This is the common console support for confluent.  It takes over
# whatever filehandle is conversing with the client and starts
# relaying data.  It uses Ctrl-] like telnet for escape back to prompt

# we track nodes that are actively being logged, watched, or have attached
# there should be no more than one handler per node
import codecs
import collections
import confluent.collective.manager as collective
import confluent.config.configmanager as configmodule
import confluent.exceptions as exc
import confluent.interface.console as conapi
import confluent.log as log
import confluent.core as plugin
import confluent.tlvdata as tlvdata
import confluent.util as util
import eventlet
import eventlet.event
import eventlet.green.os as os
import eventlet.green.select as select
import eventlet.green.socket as socket
import eventlet.green.subprocess as subprocess
import eventlet.green.ssl as ssl
import eventlet.semaphore as semaphore
import fcntl
import random
import struct
import time
import traceback

_handled_consoles = {}

_tracelog = None
_bufferdaemon = None

try:
    range = xrange
except NameError:
    pass


def chunk_output(output, n):
    for i in range(0, len(output), n):
        yield output[i:i + n]

def get_buffer_output(nodename):
    out = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    out.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    out.connect("\x00confluent-vtbuffer")
    if not isinstance(nodename, bytes):
        nodename = nodename.encode('utf8')
    outdata = bytearray()
    out.send(struct.pack('I', len(nodename)))
    out.send(nodename)
    select.select((out,), (), (), 30)
    while not outdata or outdata[-1]:
        try:
            chunk = os.read(out.fileno(), 128)
        except IOError:
            chunk = None
        if chunk:
            outdata.extend(chunk)
        else:
            select.select((out,), (), (), 0)
    return bytes(outdata[:-1])


def send_output(nodename, output):
    if not isinstance(nodename, bytes):
        nodename = nodename.encode('utf8')
    out = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    out.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    out.connect("\x00confluent-vtbuffer")
    out.send(struct.pack('I', len(nodename) | (1 << 29)))
    out.send(nodename)
    for chunk in chunk_output(output, 8192):
        out.send(struct.pack('I', len(chunk) | (2 << 29)))
        out.send(chunk)

def _utf8_normalize(data, decoder):
    # first we give the stateful decoder a crack at the byte stream,
    # we may come up empty in the event of a partial multibyte
    try:
        data = decoder.decode(data)
    except UnicodeDecodeError:
        # first order of business is to reset the state of
        # the decoder to a clean one, so we can switch back to utf-8
        # when things change, for example going from an F1 setup menu stuck
        # in the old days to a modern platform using utf-8
        decoder.setstate(codecs.getincrementaldecoder('utf-8')().getstate())
        # Ok, so we have something that is not valid UTF-8,
        # our next stop is to try CP437.  We don't try incremental
        # decode, since cp437 is single byte
        # replace is silly here, since there does not exist invalid c437,
        # but just in case
        data = data.decode('cp437', 'replace')
    # Finally, the low part of ascii is valid utf-8, but we are going to be
    # more interested in the cp437 versions (since this is console *output*
    # not input
    return data.encode('utf-8')


class ConsoleHandler(object):
    _plugin_path = '/nodes/{0}/_console/session'
    _logtobuffer = True
    _genwatchattribs = frozenset(('console.method', 'console.logging',
                                  'collective.manager'))

    def __init__(self, node, configmanager, width=80, height=24):
        self.termprefix = 'c_'
        self.clearpending = False
        self.clearerror = False
        self.initsize = (width, height)
        self._dologging = True
        self._is_local = True
        self._isondemand = False
        self.error = None
        self._retrytime = 0
        self.cfgmgr = configmanager
        self.node = node
        self.connectstate = 'unconnected'
        self._isalive = True
        #self.buffer = pyte.Screen(100, 31)
        #self.termstream = pyte.ByteStream()
        #self.termstream.attach(self.buffer)
        self.livesessions = set([])
        self.utf8decoder = codecs.getincrementaldecoder('utf-8')()
        self.pendingbytes = None
        if self._logtobuffer:
            self.logger = log.Logger(node, console=True,
                                     tenant=configmanager.tenant)
        timestamp = False
        # when reading from log file, we will use wall clock
        # it should usually match walltime.
        self.lasttime = 0
        if timestamp:
            timediff = time.time() - timestamp
            if timediff > 0:
                self.lasttime = util.monotonic_time() - timediff
            else:
                # wall clock has gone backwards, use current time as best
                # guess
                self.lasttime = util.monotonic_time()
        self.clearbuffer()
        self.reconnect = None
        self.users = {}
        self._attribwatcher = None
        self._console = None
        self.connectionthread = None
        self.send_break = None
        if self._genwatchattribs:
            self._attribwatcher = self.cfgmgr.watch_attributes(
                (self.node,), self._genwatchattribs, self._attribschanged)
        self.check_isondemand()
        if not self._isondemand:
            self.connectstate = 'connecting'
            self._connect()

    def resize(self, width, height):
        return None

    def _get_retry_time(self):
        clustsize = len(self.cfgmgr._cfgstore['nodes'])
        self._retrytime = self._retrytime * 2 + 1
        if self._retrytime > 120:
            self._retrytime = 120
        retrytime = clustsize * 0.05 * self._retrytime
        if retrytime > 120:
            retrytime = 120
        return retrytime + (retrytime * random.random())

    def feedbuffer(self, data):
        if not isinstance(data, bytes):
            data = data.encode('utf-8')
        if self.pendingbytes is not None:
            self.pendingbytes += data
        self.pendingbytes = b''
        nodeid = self.termprefix + self.node
        try:
            send_output(nodeid, data)
            data = self.pendingbytes
            self.pendingbytes = None
            if data:
                send_output(nodeid, data)
        except Exception:
            _tracelog.log(traceback.format_exc(), ltype=log.DataTypes.event,
                          event=log.Events.stacktrace)

    def check_isondemand(self):
        self._dologging = True
        attrvalue = self.cfgmgr.get_node_attributes(
            (self.node,), ('console.logging', 'collective.manager'))
        if self.node not in attrvalue:
            self._isondemand = False
        elif 'console.logging' not in attrvalue[self.node]:
            self._isondemand = False
        else:
            if (attrvalue[self.node]['console.logging']['value'] not in (
                'full', '', 'memory')):
                self._isondemand = True
            if (attrvalue[self.node]['console.logging']['value']) in ('none', 'memory'):
                self._dologging = False
        self.check_collective(attrvalue)

    def check_collective(self, attrvalue):
        myc = attrvalue.get(self.node, {}).get('collective.manager', {}).get(
            'value', None)
        if list(configmodule.list_collective()) and not myc:
            self._is_local = False
            self._detach()
            self._disconnect()
        if myc and myc != collective.get_myname():
            # Do not do console connect for nodes managed by another
            # confluent collective member
            self._is_local = False
            self._detach()
            self._disconnect()
        else:
            self._is_local = True

    def get_buffer_age(self):
        """Return age of buffered data

        Returns age in seconds of the buffered data or
        False in the event of calling before buffered data"""
        if self.lasttime:
            return util.monotonic_time() - self.lasttime
        return False

    def _attribschanged(self, nodeattribs, configmanager, **kwargs):
        if 'collective.manager' in nodeattribs[self.node]:
            attrval = configmanager.get_node_attributes(self.node,
                                                        'collective.manager')
            self.check_collective(attrval)
        if 'console.logging' in nodeattribs[self.node]:
            # decide whether logging changes how we react or not
            self._dologging = True
            logvalue = 'full'
            attributevalue = configmanager.get_node_attributes(
                (self.node,), ('console.logging',))
            try:
                logvalue = \
                    attributevalue[self.node]['console.logging']['value']
            except KeyError:
                pass
            if logvalue in ('full', ''):
                # if the *only* thing to change is the log,
                # then let always on handle reconnect if needed,
                # since we want to avoid a senseless disconnect
                # if already connected
                # if other things change, then unconditionally reconnect
                onlylogging = len(nodeattribs[self.node]) == 1
                self._alwayson(doconnect=onlylogging)
                if onlylogging:
                    return
            else:
                self._ondemand()
                if logvalue in ('none', 'memory'):
                    self._dologging = False
        if not self._isondemand or self.livesessions:
            self._connect()

    def log(self, *args, **kwargs):
        if not self._dologging:
            return
        self.logger.log(*args, **kwargs)

    def _alwayson(self, doconnect=True):
        self._isondemand = False
        if not doconnect:
            return
        if not self._console and not self.connectionthread:
            self._connect()
        else:
            self._console.ping()

    def clearbuffer(self):
        self.feedbuffer(
            '\x1bc[No data has been received from the remote console since ' \
            'connecting.  This could\r\nbe due to having the console.logging ' \
            'attribute set to none or interactive,\r\nserial console not '  \
            'being enabled or incorrectly configured in the OS or\r\nfirmware, ' \
            'or the console simply not having any output since last connection]')
        self.clearpending = True

    def _detach(self):
        for ses in list(self.livesessions):
            ses.detach()

    def _disconnect(self):
        if self.connectionthread:
            self.connectionthread.kill()
            self.connectionthread = None
        # clear the terminal buffer when disconnected
        self.clearbuffer()
        if self._console:
            self.log(
                logdata='console disconnected', ltype=log.DataTypes.event,
                event=log.Events.consoledisconnect)
            self._console.close()
            self._console = None
            self.connectstate = 'unconnected'
            self._send_rcpts({'connectstate': self.connectstate})

    def _ondemand(self):
        self._isondemand = True
        if not self.livesessions and self._console:
            self._disconnect()

    def _connect(self):
        if not self._is_local:
            return
        if self.connectionthread:
            self.connectionthread.kill()
            self.connectionthread = None
        self.connectionthread = util.spawn(self._connect_backend())

    async def _connect_backend(self):
        if self._console:
            self._console.close()
            self._console = None
        self.connectstate = 'connecting'
        self._send_rcpts({'connectstate': self.connectstate})
        if self.reconnect:
            self.reconnect.cancel()
            self.reconnect = None
        strerror = ('The console.method attribute for this node is '
                'not configured,\r\nset it to a valid value for console '
                'function')
        try:
            self._console = list(await plugin.handle_path(
                self._plugin_path.format(self.node),
                "create", self.cfgmgr))[0]
        except (exc.NotImplementedException, exc.NotFoundException):
            self._console = None
        except Exception as e:
            strerror = str(e)
            if _tracelog:
                _tracelog.log(traceback.format_exc(), ltype=log.DataTypes.event,
                              event=log.Events.stacktrace)
            else:
                print(traceback.format_exc())
        if not isinstance(self._console, conapi.Console):
            self.clearbuffer()
            self.connectstate = 'unconnected'
            self.error = 'misconfigured'
            self._send_rcpts({'connectstate': self.connectstate,
                              'error': self.error})
            self.feedbuffer(
                '\x1bc\x1b[2J\x1b[1;1H[{0}]'.format(strerror))
            self._send_rcpts(
                '\x1bc\x1b[2J\x1b[1;1H[{0}]'.format(strerror))
            self.clearerror = True
            return
        if self.clearerror:
            self.clearerror = False
            self.clearbuffer()
            self._send_rcpts(b'\x1bc\x1b[2J\x1b[1;1H')
        self.send_break = self._console.send_break
        self.resize = self._console.resize
        if self._attribwatcher:
            self.cfgmgr.remove_watcher(self._attribwatcher)
            self._attribwatcher = None
        if hasattr(self._console, "configattributes"):
            attribstowatch = self._console.configattributes | self._genwatchattribs
        else:
            attribstowatch = self._genwatchattribs
        if self._genwatchattribs:
            self._attribwatcher = self.cfgmgr.watch_attributes(
                (self.node,), attribstowatch, self._attribschanged)
        try:
            self.resize(width=self.initsize[0], height=self.initsize[1])
            self._console.connect(self.get_console_output)
        except exc.TargetEndpointBadCredentials:
            self.clearbuffer()
            self.error = 'badcredentials'
            self.connectstate = 'unconnected'
            self._send_rcpts({'connectstate': self.connectstate,
                              'error': self.error})
            retrytime = self._get_retry_time()
            if not self.reconnect:
                self.reconnect = util.spawn_after(retrytime, self._connect)
            return
        except (exc.TargetEndpointUnreachable, socket.gaierror) as se:
            self.clearbuffer()
            self.error = 'unreachable'
            self.connectstate = 'unconnected'
            self._send_rcpts({'connectstate': self.connectstate,
                              'error': self.error})
            retrytime = self._get_retry_time()
            if not self.reconnect:
                self.reconnect = util.spawn_after(retrytime, self._connect)
            return
        except Exception:
            self.clearbuffer()
            _tracelog.log(traceback.format_exc(), ltype=log.DataTypes.event,
                          event=log.Events.stacktrace)
            self.error = 'unknown'
            self.connectstate = 'unconnected'
            self._send_rcpts({'connectstate': self.connectstate,
                              'error': self.error})
            retrytime = self._get_retry_time()
            if not self.reconnect:
                self.reconnect = util.spawn_after(retrytime, self._connect)
            return
        self._got_connected()

    def _got_connected(self):
        self.connectstate = 'connected'
        self._retrytime = 0
        self.log(
            logdata='console connected', ltype=log.DataTypes.event,
            event=log.Events.consoleconnect)
        self._send_rcpts({'connectstate': self.connectstate})

    def _got_disconnected(self):
        if self.connectstate != 'unconnected':
            self._console.close()
            self.connectstate = 'unconnected'
            self.log(
                logdata='console disconnected', ltype=log.DataTypes.event,
                event=log.Events.consoledisconnect)
            self._send_rcpts({'connectstate': self.connectstate})
        if self._isalive:
            self._connect()
        else:
            self.clearbuffer()

    def close(self):
        self._isalive = False
        self._send_rcpts({'deleting': True})
        self._disconnect()
        if self._console:

            self._console.close()
            self._console = None
        if self.connectionthread:
            self.connectionthread.kill()
            self.connectionthread = None
        if self._attribwatcher:
            self.cfgmgr.remove_watcher(self._attribwatcher)
            self._attribwatcher = None

    def get_console_output(self, data):
        # Spawn as a greenthread, return control as soon as possible
        # to the console object
        eventlet.spawn(self._handle_console_output, data)

    def attachsession(self, session):
        edata = 1
        for currsession in self.livesessions:
            if currsession.username == session.username:
                # indicate that user has multiple connections
                edata = 2
        self.livesessions.add(session)
        self.log(
            logdata=session.username, ltype=log.DataTypes.event,
            event=log.Events.clientconnect, eventdata=edata)
        self._send_rcpts({'clientcount': len(self.livesessions)})
        if self.connectstate == 'unconnected':
            # if console is not connected, take time to try to assert
            # connectivity now.
            if self.reconnect:
                # cancel an automated retry if one is pending
                self.reconnect.cancel()
                self.reconnect = None
            self.connectstate = 'connecting'
            self._connect()



    def detachsession(self, session):
        edata = 0
        self.livesessions.discard(session)
        for currsession in self.livesessions:
            if currsession.username == session.username:
                edata += 1
            if edata > 1:  # don't bother counting beyond 2 in the log
                break
        self.log(
            logdata=session.username, ltype=log.DataTypes.event,
            event=log.Events.clientdisconnect, eventdata=edata)
        self._send_rcpts({'clientcount': len(self.livesessions)})
        if self._isondemand and not self.livesessions:
            self._disconnect()


    def reopen(self):
        self._got_disconnected()

    def _handle_console_output(self, data):
        if type(data) == int:
            if data == conapi.ConsoleEvent.Disconnect:
                self._got_disconnected()
            return
        elif data in (b'', u''):
            # ignore empty strings from a cconsole provider
            return
        if not isinstance(data, bytes):
            data = data.encode('utf-8')
        eventdata = 0
        # TODO: analyze buffer for registered events, examples:
        #   panics
        #   certificate signing request
        if self.clearpending or self.clearerror:
            self.clearpending = False
            self.clearerror = False
            self.feedbuffer(b'\x1bc\x1b[2J\x1b[1;1H')
            self._send_rcpts(b'\x1bc\x1b[2J\x1b[1;1H')
        self._send_rcpts(_utf8_normalize(data, self.utf8decoder))
        self.log(data, eventdata=eventdata)
        self.lasttime = util.monotonic_time()
        self.feedbuffer(data)


    def _send_rcpts(self, data):
        for rcpt in list(self.livesessions):
            try:
                rcpt.data_handler(data)
            except:  # No matter the reason, advance to next recipient
                _tracelog.log(traceback.format_exc(), ltype=log.DataTypes.event,
                          event=log.Events.stacktrace)

    def get_recent(self):
        """Retrieve 'recent' data

        Replay data in the intent to perhaps reproduce the display.
        """
        # For now, just try to seek back in buffer to find a clear screen
        # If that fails, just return buffer
        # a scheme always tracking the last clear screen would be too costly
        connstate = {
            'connectstate': self.connectstate,
            'clientcount': len(self.livesessions),
        }
        nodeid = self.termprefix + self.node
        retdata = get_buffer_output(nodeid)
        return retdata, connstate

    def write(self, data):
        if self.connectstate == 'connected':
            try:
                if isinstance(data, str) and not isinstance(data, bytes):
                    data = data.encode('utf-8')
                self._console.write(data)
            except Exception:
                _tracelog.log(traceback.format_exc(), ltype=log.DataTypes.event,
                              event=log.Events.stacktrace)
                self._got_disconnected()


def disconnect_node(node, configmanager):
    consk = (node, configmanager.tenant)
    if consk in _handled_consoles:
        _handled_consoles[consk].close()
        del _handled_consoles[consk]


def _nodechange(added, deleting, renamed, configmanager):
    for node in deleting:
        disconnect_node(node, configmanager)
    for node in renamed:
        disconnect_node(node, configmanager)
        connect_node(renamed[node], configmanager)
    for node in added:
        connect_node(node, configmanager)


def _start_tenant_sessions(cfm):
    nodeattrs = cfm.get_node_attributes(cfm.list_nodes(), 'collective.manager')
    for node in nodeattrs:
        manager = nodeattrs[node].get('collective.manager', {}).get('value',
                                                                    None)
        if manager and collective.get_myname() != manager:
            continue
        try:
            connect_node(node, cfm)
        except:
            _tracelog.log(traceback.format_exc(), ltype=log.DataTypes.event,
                          event=log.Events.stacktrace)
    cfm.watch_nodecollection(_nodechange)


def initialize():
    global _tracelog
    global _bufferdaemon
    _tracelog = log.Logger('trace')
    _bufferdaemon = subprocess.Popen(
        ['/opt/confluent/bin/vtbufferd', 'confluent-vtbuffer'], bufsize=0, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL)

def start_console_sessions():
    configmodule.hook_new_configmanagers(_start_tenant_sessions)


def connect_node(node, configmanager, username=None, direct=True, width=80,
                 height=24):
    attrval = configmanager.get_node_attributes(node, 'collective.manager')
    myc = attrval.get(node, {}).get('collective.manager', {}).get(
        'value', None)
    myname = collective.get_myname()
    if myc and myc != collective.get_myname() and direct:
        minfo = configmodule.get_collective_member(myc)
        if not minfo:
            raise Exception('Unable to get collective member for {}'.format(node))
        return ProxyConsole(node, minfo, myname, configmanager, username,
                            width, height)
    consk = (node, configmanager.tenant)
    if consk not in _handled_consoles:
        _handled_consoles[consk] = ConsoleHandler(node, configmanager, width,
                                                  height)
    return _handled_consoles[consk]

# A stub console handler that just passes through to a remote confluent
# collective member.  It can skip the multi-session sharing as that is handled
# remotely
class ProxyConsole(object):
    _genwatchattribs = frozenset(('collective.manager',))

    def __init__(self, node, managerinfo, myname, configmanager, user, width,
                 height):
        self.skipreplay = True
        self.initsize = (width, height)
        self.managerinfo = managerinfo
        self.myname = myname
        self.cfm = configmanager
        self.node = node
        self.user = user
        self.remote = None
        self.clisession = None
        self._attribwatcher = configmanager.watch_attributes(
            (self.node,), self._genwatchattribs, self._attribschanged)


    def _attribschanged(self, nodeattribs, configmanager, **kwargs):
        if self.clisession:
            self.clisession.detach()
            self.clisession = None

    def relay_data(self):
        data = tlvdata.recv(self.remote)
        while data:
            self.data_handler(data)
            data = tlvdata.recv(self.remote)
        self.remote.close()

    def get_buffer_age(self):
        # the server sends a buffer age if appropriate, no need to handle
        # it explicitly in the proxy instance
        return False

    def get_recent(self):
        # Again, delegate this to the remote collective member
        self.skipreplay = False
        return b''

    def write(self, data):
        # Relay data to the collective manager
        try:
            tlvdata.send(self.remote, data)
        except Exception:
            if self.clisession:
                self.clisession.detach()
            self.clisession = None


    def attachsession(self, session):
        self.clisession = session
        self.data_handler = session.data_handler
        termreq = {
            'proxyconsole': {
                'name': self.myname,
                'user': self.user,
                'tenant': self.cfm.tenant,
                'node': self.node,
                'skipreplay': self.skipreplay,
                'width': self.initsize[0],
                'height': self.initsize[1],
                #TODO(jjohnson2): declare myself as a proxy,
                #facilitate redirect rather than relay on manager change
            },
        }
        try:
            remote = socket.create_connection((self.managerinfo['address'], 13001))
            remote = ssl.wrap_socket(remote, cert_reqs=ssl.CERT_NONE,
                                     keyfile='/etc/confluent/privkey.pem',
                                     certfile='/etc/confluent/srvcert.pem')
            if not util.cert_matches(self.managerinfo['fingerprint'],
                                     remote.getpeercert(binary_form=True)):
                raise Exception('Invalid peer certificate')
        except Exception:
            eventlet.sleep(3)
            if self.clisession:
                self.clisession.detach()
            self.detachsession(None)
            return
        tlvdata.recv(remote)
        tlvdata.recv(remote)
        tlvdata.send(remote, termreq)
        self.remote = remote
        eventlet.spawn(self.relay_data)

    def detachsession(self, session):
        # we will disappear, so just let that happen...
        if self.remote:
            try:
                tlvdata.send(self.remote, {'operation': 'stop'})
            except Exception:
                pass
        self.clisession = None

    def send_break(self):
        tlvdata.send(self.remote, {'operation': 'break'})

    def reopen(self):
        tlvdata.send(self.remote, {'operation': 'reopen'})

    def resize(self, width, height):
        tlvdata.send(self.remote, {'operation': 'resize', 'width': width,
                                   'height': height})


# this represents some api view of a console handler.  This handles things like
# holding the caller specific queue data, for example, when http api should be
# sending data, but there is no outstanding POST request to hold it,
# this object has the job of holding the data


class ConsoleSession(object):
    """Create a new socket to converse with node console

    This object provides a filehandle that can be read/written
    too in a normal fashion and the concurrency, logging, and
    event watching will all be handled seamlessly

    :param node: Name of the node for which this session will be created
    :param configmanager: A configuration manager object for current context
    :param username: Username for which this session object will operate
    :param datacallback: An asynchronous data handler, to be called when data
                         is available.  Note that if passed, it makes
                         'get_next_output' non-functional
    :param skipreplay: If true, will skip the attempt to redraw the screen
    """

    def __init__(self, node, configmanager, username, datacallback=None,
                 skipreplay=False, direct=True, width=80, height=24):
        self.registered = False
        self.tenant = configmanager.tenant
        if not configmanager.is_node(node):
            raise exc.NotFoundException("Invalid node")
        self.username = username
        self.node = node
        self.configmanager = configmanager
        self.direct = direct  # true if client is directly connected versus
                              # relay
        self.width = width
        self.height = height
        self.connect_session()
        self.registered = True
        self._evt = None
        self.node = node
        self.write = self.conshdl.write
        if datacallback is None:
            self.reaper = util.spawn_after(15, self.destroy)
            self.databuffer = collections.deque([])
            self.data_handler = self.got_data
            if not skipreplay:
                self.databuffer.extend(self.conshdl.get_recent())
        else:
            self.data_handler = datacallback
            if not skipreplay:
                for recdata in self.conshdl.get_recent():
                    if recdata:
                        datacallback(recdata)
        self.conshdl.attachsession(self)


    def connect_session(self):
        """Connect to the appropriate backend handler

        This is not intended to be called by your usual consumer,
        it is a hook for confluent to abstract the concept of a terminal
        between console and shell.
        """
        self.conshdl = connect_node(self.node, self.configmanager,
                                    self.username, self.direct, self.width,
                                    self.height)
    def send_break(self):
        """Send break to remote system
        """
        self.conshdl.send_break()

    def resize(self, width, height):
        self.conshdl.resize(width, height)

    def get_buffer_age(self):
        """Get the age in seconds of the buffered data

        Returns False if no data buffered yet"""
        return self.conshdl.get_buffer_age()

    def reopen(self):
        """Reopen the session

        This can be useful if there is suspicion that the remote console is
        dead.  Note that developers should consider need for this a bug unless
        there really is some fundamental, unavoidable limitation regarding
        automatically detecting an unusable console in the underlying
        technology that cannot be unambiguously autodetected.
        """
        self.conshdl.reopen()

    def destroy(self):
        if self.registered:
            self.conshdl.detachsession(self)
        if self._evt:
            self._evt.send()
        self._evt = None
        self.reghdl = None

    def detach(self):
        """Handler for the console handler to detach so it can reattach,
        currently to facilitate changing from one collective.manager to
        another

        :return:
        """
        self.conshdl.detachsession(self)
        self.connect_session()
        self.conshdl.attachsession(self)
        self.write = self.conshdl.write

    def got_data(self, data):
        """Receive data from console and buffer

        If the caller does not provide a callback and instead will be polling
        for data, we must maintain data in a buffer until retrieved.  This is
        an internal function used as a means to convert the async behavior to
        polling for consumers that cannot do the async behavior.
        """
        self.databuffer.append(data)
        if self._evt:
            self._evt.send()
            self._evt = None

    def get_next_output(self, timeout=45):
        """Poll for next available output on this console.

        Ideally purely event driven scheme is perfect.  AJAX over HTTP is
        at least one case where we don't have that luxury.  This function
        will not work if the session was initialized with a data callback
        instead of polling mode.
        """
        self.reaper.cancel()
        # postpone death to be 15 seconds after this would timeout
        self.reaper = util.spawn_after(timeout + 15, self.destroy)
        if self._evt:
            raise Exception('get_next_output is not re-entrant')
        if not self.databuffer:
            self._evt = eventlet.event.Event()
            with eventlet.Timeout(timeout, False):
                self._evt.wait()
            self._evt = None
        if not self.databuffer:
            return ""
        currdata = self.databuffer.popleft()
        if isinstance(currdata, dict):
            return currdata
        retval = currdata
        while self.databuffer and not isinstance(self.databuffer[0], dict):
            retval += self.databuffer.popleft()

        return retval
