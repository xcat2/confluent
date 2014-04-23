# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 IBM Corporation
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

# This module contains function to write out log type data.
# In this go around, log data is explicitly kept distinct from config data
# config data almost always retrieved by a particular key value and access
# pattern is random.  For logs, the access tends to be sequential.
#
# Current thought is to have a plain-text file and a secondary binary index
# file.  The index would track events and time intervals and the seek() value.
# Markers would be put into the plain text, allowing utility to rebuild
# index if something happens beyond the scope of this module's code.
#
# We can contemplate how to add value as an audit log.  The following
# possibilities could be explored:
#   - Forward Secure Sealing (like systemd).  Examine the algorithm and decide
#     if it is sufficient (their implementation, for example, seems hard
#     to protect against tampering as at least a few moments into the past
#     can always be manipulated....
#   - TPM PCRs.  Understand better what PCRs may be used/extended perhaps
#     per-indexed event..

# On the plaintext half of a log:
# Strategy is that console log shall have just the payload logged, sans
# timestamp.
# Other events (e.g. SEL or other actions) will get timestamps
# preceding '[]' to denote them.  Timestamps will be in local
# time in the text output
# If a log is set to not be primarily console type data, then '[]' are not
# used, timestamp still precedes record, and records get '\n' appended
# If binary data is really called for, base64 format shall be used to
# avoid messing up text reads.

# On the binary half of a log (.jnl):
# The specific format can be whatever we decide since there is a text format.
# The information to store:
#    - leading bit reserved, 0 for now
#    - length of metadata record 7 bits
#    - type of data referenced by this entry (one byte), currently:
#       0=text event, 1=json, 2=console data
#    - offset into the text log to begin (4 bytes)
#    - length of data referenced by this entry (2 bytes)
#    - UTC timestamp of this entry in seconds since epoch (unsigned 32 bit?)
#    - CRC32 over the record
#    (a future extended version might include suport for Forward Secure Sealing
#    or other fields)

import collections
import confluent.config.configmanager as configuration
import eventlet
import fcntl
import json
import os
import struct
import time

# on conserving filehandles:
# upon write, if file not open, open it for append
# upon write, schedule/reschedule closing filehandle in 15 seconds
# this way, idle log files get closed, mitigating risk of running afoul
# of uname type limts, but the filehandle stays open under load and
# buffering and such work when things are busy
# perhaps test with very low ulimit and detect shortage and
# switch to aggressive handle reclaim, tanking performance
# if that happens, warn to have user increase ulimit for optimal
# performance

_loggers = {}


class Events(object):
    (
        undefined, clearscreen, clientconnect, clientdisconnect,
        consoledisconnect, consoleconnect, stacktrace
    ) = range(7)
    logstr = {
        2: 'connection by ',
        3: 'disconnection by ',
    }


class DataTypes(object):
    text, dictionary, console, event = range(4)


class Logger(object):
    """
    :param console:  If true, [] will be used to denote non-text events.  If
                     False, events will be formatted like syslog:
                     date: message<CR>
    """
    def __new__(cls, logname, console=False, tenant=None):
        global _loggers
        if console:
            relpath = 'consoles/' + logname
        else:
            relpath = logname
        if relpath in _loggers:
            return _loggers[relpath]
        else:
            return object.__new__(cls)

    def __init__(self, logname, console=False, tenant=None):
        if hasattr(self, 'initialized'):
            # we are just a copy of the same object
            return
        self.initialized = True
        self.filepath = configuration.get_global("logdirectory")
        if self.filepath is None:
            self.filepath = "/var/log/confluent/"
        self.isconsole = console
        if console:
            self.filepath += "consoles/"
        if not os.path.isdir(self.filepath):
            os.makedirs(self.filepath, 448)
        self.textpath = self.filepath + logname
        self.binpath = self.filepath + logname + ".cbl"
        self.writer = None
        self.closer = None
        self.textfile = None
        self.binfile = None
        self.logentries = collections.deque()

    def writedata(self):
        if self.textfile is None:
            self.textfile = open(self.textpath, mode='ab')
        if self.binfile is None:
            self.binfile = open(self.binpath, mode='ab')
        while self.logentries:
            entry = self.logentries.popleft()
            ltype = entry[0]
            tstamp = entry[1]
            data = entry[2]
            evtdata = entry[3]
            textdate = ''
            if self.isconsole and ltype != 2:
                textdate = time.strftime(
                    '[%m/%d %H:%M:%S ', time.localtime(tstamp))
                if ltype == DataTypes.event and evtdata in Events.logstr:
                    textdate += Events.logstr[evtdata]
            elif not self.isconsole:
                textdate = time.strftime(
                    '%b %d %H:%M:%S ', time.localtime(tstamp))
            fcntl.flock(self.textfile, fcntl.LOCK_EX)
            offset = self.textfile.tell() + len(textdate)
            datalen = len(data)
            eventaux = entry[4]
            if eventaux is None:
                eventaux = 0
            # metadata length is always 16 for this code at the moment
            binrecord = struct.pack(
                ">BBIHIBBH", 16, ltype, offset, datalen, tstamp, evtdata,
                eventaux, 0)
            if self.isconsole:
                if ltype == 2:
                    textrecord = data
                else:
                    textrecord = textdate + data + ']'
            else:
                textrecord = textdate + data
                if not textrecord.endswith('\n'):
                    textrecord += '\n'
            self.textfile.write(textrecord)
            fcntl.flock(self.textfile, fcntl.LOCK_UN)
            fcntl.flock(self.binfile, fcntl.LOCK_EX)
            self.binfile.write(binrecord)
            fcntl.flock(self.binfile, fcntl.LOCK_UN)
        self.textfile.flush()
        self.binfile.flush()
        if self.closer is None:
            self.closer = eventlet.spawn_after(15, self.closelog)
        self.writer = None

    def read_recent_text(self, size):
        try:
            textfile = open(self.textpath, mode='r')
            binfile = open(self.binpath, mode='r')
        except IOError:
            return '', 0
        fcntl.flock(binfile, fcntl.LOCK_SH)
        binfile.seek(0, 2)
        binidx = binfile.tell() - 16
        currsize = 0
        offsets = []
        termstate = None
        while binidx > 0 and currsize < size:
            binfile.seek(binidx, 0)
            binidx -= 16
            recbytes = binfile.read(16)
            (_, ltype, offset, datalen, tstamp, evtdata, eventaux, _) = \
                struct.unpack(">BBIHIBBH", recbytes)
            if ltype != 2:
                continue
            currsize += datalen
            offsets.append((offset, datalen))
            if termstate is None:
                termstate = eventaux
        fcntl.flock(binfile, fcntl.LOCK_UN)
        binfile.close()
        textdata = ''
        fcntl.flock(textfile, fcntl.LOCK_SH)
        while offsets:
            (offset, length) = offsets.pop()
            textfile.seek(offset, 0)
            textdata += textfile.read(length)
        fcntl.flock(textfile, fcntl.LOCK_UN)
        textfile.close()
        if termstate is None:
            termstate = 0
        return textdata, termstate

    def write(self, data):
        """Write plain text to log

        This is intended so that a log object may be used to replace a
        normal file object with a loss of capability.  For example,
        sys.stdout = logobject

        :param data: data to log
        """
        if data != '\n':  # 'print' likes to do '\n' by itself, skip that
            self.log(data)

    def flush(self):
        pass

    def log(self, logdata=None, ltype=None, event=0, eventdata=None):
        if type(logdata) not in (str, unicode, dict):
            raise Exception("Unsupported logdata")
        if ltype is None:
            if type(logdata) == dict:
                logdata = json.dumps(logdata)
                ltype = 1
            elif self.isconsole:
                ltype = 2
            else:
                ltype = 0
        if self.closer is not None:
            self.closer.cancel()
            self.closer = None
        timestamp = int(time.time())
        if (len(self.logentries) > 0 and ltype == 2 and
                event == 0 and self.logentries[-1][0] == 2 and
                self.logentries[-1][1] == timestamp):
            self.logentries[-1][2] += logdata
            if eventdata is not None:
                self.logentries[-1][4] = eventdata
        else:
            self.logentries.append(
                [ltype, timestamp, logdata, event, eventdata])
        if self.writer is None:
            self.writer = eventlet.spawn_after(2, self.writedata)

    def closelog(self):
        self.textfile.close()
        self.binfile.close()
        self.textfile = None
        self.binfile = None
        self.closer = None
