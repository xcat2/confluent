# Copyright 2013 IBM
# All rights reserved

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


class Events(object):
    undefined, clearscreen, clientconnect, clientdisconnect = range(4)
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
    def __init__(self, logname, console=True, tenant=None):
        self.filepath = configuration.get_global("logdirectory")
        if self.filepath is None:
            self.filepath = "/var/log/confluent/"
        self.isconsole = console
        if console:
            self.filepath += "consoles/"
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
            offset = self.textfile.tell() + len(textdate)
            datalen = len(data)
            # metadata length is always 16 for this code at the moment
            binrecord = struct.pack(">BBIHIBBH",
                    16, ltype, offset, datalen, tstamp, evtdata, entry[4], 0)
            if self.isconsole:
                if ltype == 2:
                    textrecord = data
                else:
                    textrecord = textdate + data + ']'
            else:
                textrecord = textdate + data + '\n'
            self.textfile.write(textrecord)
            self.binfile.write(binrecord)
        self.textfile.flush()
        self.binfile.flush()
        if self.closer is None:
            self.closer = eventlet.spawn_after(15, self.closelog)
        self.writer = None

    def log(self, logdata=None, ltype=None, event=0, eventdata=0):
        if type(logdata) not in (str, unicode, dict):
            raise Exception("Unsupported logdata")
        if ltype is None:
            if type(logdata) == dict:
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
        else:
            self.logentries.append([ltype, timestamp, logdata, event, eventdata])
        if self.writer is None:
            self.writer = eventlet.spawn_after(2, self.writedata)

    def closelog(self):
        self.textfile.close()
        self.binfile.close()
        self.textfile = None
        self.binfile = None
        self.closer = None
