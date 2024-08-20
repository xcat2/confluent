# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 IBM Corporation
# Copyright 2015-2016 Lenovo
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
#       0=text event, 1=json, 2=console data, 3=event
#    - offset into the text log to begin (4 bytes)
#    - length of data referenced by this entry (2 bytes)
#    - UTC timestamp of this entry in seconds since epoch (unsigned 32 bit)
#    - Event type (per 'Events' class below)
#    - Event data (per event, currently used by connect/disconnect to represent
#      single or multiple connections by user and for 'appmode' and 'shiftin'
#      status for console
#    - 2 reserved bytes
#    (a future extended version might include suport for Forward Secure Sealing
#    or other fields)

import asyncio
import collections
import confluent.config.configmanager
import confluent.config.conf as conf
import confluent.exceptions as exc
import inspect
import glob
import json
import os
import re
import stat
import struct
import time
import traceback
import random
try:
    unicode
except NameError:
    unicode = str

daemonized = False
logfull = False
try:
    from fcntl import flock, LOCK_EX, LOCK_UN, LOCK_SH
except ImportError:
    if os.name == 'nt':
        import msvcrt
        LOCK_SH = msvcrt.LK_LOCK  # no shared, degrade to exclusive
        LOCK_EX = msvcrt.LK_LOCK
        LOCK_UN = msvcrt.LK_UNLCK
        def flock(file, flag):
            oldoffset = file.tell()
            file.seek(0)
            msvcrt.locking(file.fileno(), flag, 1)
            file.seek(oldoffset)
    else:
        raise

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

MIDNIGHT = 24 * 60 * 60
_loggers = {}


async def _sleep_and_run(sleeptime, func, args):
    await asyncio.sleep(sleeptime)
    awt = func(*args)
    if inspect.isawaitable(awt):
        await awt


def spawn_after(sleeptime, func, *args):
    if func is None:
        raise Exception('tf')
    return spawn(_sleep_and_run(sleeptime, func, args))


tsks = {}


def spawn(coro):
    tskid = random.random()
    while tskid in tsks:
        tskid = random.random()
    tsks[tskid] = 1
    try:
        tsks[tskid] = asyncio.create_task(_run(coro, tskid), name=repr(coro))
    except AttributeError:
        tsks[tskid] = asyncio.get_event_loop().create_task(_run(coro, tskid), name=repr(coro))
    return tsks[tskid]


async def _run(coro, taskid):
    ret = await coro
    del tsks[taskid]
    return ret


class Events(object):
    (
        undefined, clearscreen, clientconnect, clientdisconnect,
        consoledisconnect, consoleconnect, stacktrace, logrollover
    ) = range(8)
    logstr = {
        2: 'connection by ',
        3: 'disconnection by ',
    }


class DataTypes(object):
    text, dictionary, console, event = range(4)


class RollingTypes(object):
    no_rolling, size_rolling, time_rolling = range(3)


class BaseRotatingHandler(object):

    def __init__(self, filepath, logname):
        """
        Use the specified filename for streamed logging
        """
        self.filepath = filepath
        self.textpath = os.path.join(self.filepath, logname)
        self.binpath = os.path.join(self.filepath, logname + ".cbl")
        self.textfile = None
        self.binfile = None

    def open(self):
        if self.textfile is None:
            self.textfile = open(self.textpath, mode='ab')
            self.textfile.seek(0, 2)
        if self.binfile is None:
            self.binfile = open(self.binpath, mode='ab')
            self.binfile.seek(0, 2)
        return self.textfile, self.binfile

    def try_emit(self, binrecord, textrecord):
        """
        Emit a record.

        Output the record to the file, catering for rollover as described
        in doRollover().
        """
        global logfull
        try:
            rolling_type = self.shouldRollover(binrecord, textrecord)
            if rolling_type:
                flock(self.textfile, LOCK_UN)
                return self.doRollover(rolling_type)
            return None
        except (IOError, OSError) as e:
            if not daemonized:
                raise
            logfull = True


    def emit(self, binrecord, textrecord):
        global logfull
        try:
            if self.textfile is None:
                self.textfile = open(self.textpath, mode='ab')
            if self.binfile is None:
                self.binfile = open(self.binpath, mode='ab')
            if not isinstance(textrecord, bytes):
                textrecord = textrecord.encode('utf-8')
            self.textfile.write(textrecord)
            self.binfile.write(binrecord)
            self.textfile.flush()
            self.binfile.flush()
        except (IOError, OSError) as e:
            if not daemonized:
                raise
            logfull = True

    def get_textfile_offset(self, data_len):
        if self.textfile is None:
            self.textfile = open(self.textpath, mode='ab')
        return self.textfile.tell() + data_len

    def close(self):
        if self.textfile:
            if not self.textfile.closed:
                self.textfile.close()
            self.textfile = None
        if self.binfile:
            if not self.binfile.closed:
                self.binfile.close()
            self.binfile = None


class TimedAndSizeRotatingFileHandler(BaseRotatingHandler):
    """
    Handler for logging to a file, rotating the log file at certain timed
    intervals.

    If backupCount is > 0, when rollover is done, no more than backupCount
    files are kept - the oldest ones are deleted.
    """

    def __init__(self, filepath, logname, interval=1):
        BaseRotatingHandler.__init__(self, filepath, logname)
        try:
            self.when = conf.get_option('log', 'when').upper()
        except (AttributeError):
            self.when = 'D'
        self.backupCount = conf.get_int_option('log', 'backup_count') or 0
        self.maxBytes = conf.get_int_option(
            'log','max_bytes') or 4 * 1024 * 1024 * 1024
        if self.maxBytes < 8192:
            raise exc.GlobalConfigError("The minimum value of max_bytes "
                                        "of log rolling size in the log "
                                        "section should larger than 8192.")
        self.utc = conf.get_boolean_option('log', 'utc') or False

        # Calculate the real rollover interval, which is just the number of
        # seconds between rollovers.  Also set the filename suffix used when
        # a rollover occurs.  Current 'when' events supported:
        # S - Seconds
        # M - Minutes
        # H - Hours
        # D - Days
        # midnight - roll over at midnight
        # W{0-6} - roll over on a certain day; 0 - Monday
        #
        # Case of the 'when' specifier is not important; lower or upper case
        # will work.
        if self.when == 'S':
            self.interval = 1 # one second
            self.suffix = "%Y-%m-%d_%H-%M-%S"
            self.extMatch = r"^(cbl\.){0,1}\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.{0,1}\d*$"
        elif self.when == 'M':
            self.interval = 60 # one minute
            self.suffix = "%Y-%m-%d_%H-%M"
            self.extMatch = r"^(cbl\.){0,1}\d{4}-\d{2}-\d{2}_\d{2}-\d{2}\.{0,1}\d*$"
        elif self.when == 'H':
            self.interval = 60 * 60 # one hour
            self.suffix = "%Y-%m-%d_%H"
            self.extMatch = r"^(cbl\.){0,1}\d{4}-\d{2}-\d{2}_\d{2}$"
        elif self.when == 'D' or self.when == 'MIDNIGHT':
            self.interval = 60 * 60 * 24 # one day
            self.suffix = "%Y-%m-%d"
            self.extMatch = r"^(cbl\.){0,1}\d{4}-\d{2}-\d{2}\.{0,1}\d*$"
        elif self.when.startswith('W'):
            self.interval = 60 * 60 * 24 * 7 # one week
            if len(self.when) != 2:
                raise ValueError("You must specify a day for weekly rollover from 0 to 6 (0 is Monday): %s" % self.when)
            if self.when[1] < '0' or self.when[1] > '6':
                raise ValueError("Invalid day specified for weekly rollover: %s" % self.when)
            self.dayOfWeek = int(self.when[1])
            self.suffix = "%Y-%m-%d"
            self.extMatch = r"^(cbl\.){0,1}\d{4}-\d{2}-\d{2}\.{0,1}\d*$"
        else:
            raise ValueError("Invalid rollover interval specified: %s" % self.when)

        self.extMatch = re.compile(self.extMatch)
        self.interval = self.interval * interval # multiply by units requested
        # Note: Get the modify time of text log file to calculate the
        # rollover time
        if os.path.exists(self.textpath):
            t = os.stat(self.textpath)[stat.ST_MTIME]
        else:
            t = int(time.time())
        self.rolloverAt = self.computeRollover(t)
        self.sizeRollingCount = 0
        self.initSizeRollingCount()

    def computeRollover(self, currentTime):
        """
        Work out the rollover time based on the specified time.
        """
        result = currentTime + self.interval
        # If we are rolling over at midnight or weekly, then the interval is already known.
        # What we need to figure out is WHEN the next interval is.  In other words,
        # if you are rolling over at midnight, then your base interval is 1 day,
        # but you want to start that one day clock at midnight, not now.  So, we
        # have to fudge the rolloverAt value in order to trigger the first rollover
        # at the right time.  After that, the regular interval will take care of
        # the rest.  Note that this code doesn't care about leap seconds. :)
        if self.when == 'MIDNIGHT' or self.when.startswith('W'):
            # This could be done with less code, but I wanted it to be clear
            if self.utc:
                t = time.gmtime(currentTime)
            else:
                t = time.localtime(currentTime)
            currentHour = t[3]
            currentMinute = t[4]
            currentSecond = t[5]
            # r is the number of seconds left between now and midnight
            r = MIDNIGHT - ((currentHour * 60 + currentMinute) * 60 +
                    currentSecond)
            result = currentTime + r
            # If we are rolling over on a certain day, add in the number of days until
            # the next rollover, but offset by 1 since we just calculated the time
            # until the next day starts.  There are three cases:
            # Case 1) The day to rollover is today; in this case, do nothing
            # Case 2) The day to rollover is further in the interval (i.e., today is
            #         day 2 (Wednesday) and rollover is on day 6 (Sunday).  Days to
            #         next rollover is simply 6 - 2 - 1, or 3.
            # Case 3) The day to rollover is behind us in the interval (i.e., today
            #         is day 5 (Saturday) and rollover is on day 3 (Thursday).
            #         Days to rollover is 6 - 5 + 3, or 4.  In this case, it's the
            #         number of days left in the current week (1) plus the number
            #         of days in the next week until the rollover day (3).
            # The calculations described in 2) and 3) above need to have a day added.
            # This is because the above time calculation takes us to midnight on this
            # day, i.e. the start of the next day.
            if self.when.startswith('W'):
                day = t[6] # 0 is Monday
                if day != self.dayOfWeek:
                    if day < self.dayOfWeek:
                        daysToWait = self.dayOfWeek - day
                    else:
                        daysToWait = 6 - day + self.dayOfWeek + 1
                    newRolloverAt = result + (daysToWait * (60 * 60 * 24))
                    if not self.utc:
                        dstNow = t[-1]
                        dstAtRollover = time.localtime(newRolloverAt)[-1]
                        if dstNow != dstAtRollover:
                            if not dstNow:  # DST kicks in before next rollover, so we need to deduct an hour
                                addend = -3600
                            else:           # DST bows out before next rollover, so we need to add an hour
                                addend = 3600
                            newRolloverAt += addend
                    result = newRolloverAt
        return result

    def shouldRollover(self, binrecord, textrecord):
        """
        Determine if rollover should occur.
        Just compare times.
        """
        # time rolling first
        t = int(time.time())
        if t >= self.rolloverAt:
            return RollingTypes.time_rolling
        self.open()
        if self.maxBytes > 0:                   # are we rolling over?
            if self.textfile.tell() + len(textrecord) >= self.maxBytes:
                return RollingTypes.size_rolling
            if self.binfile.tell() + len(binrecord) >= self.maxBytes:
                return RollingTypes.size_rolling
        return RollingTypes.no_rolling

    def getFilesToDelete(self):
        """
        Determine the files to delete when rolling over.
        """
        dirName, baseName = os.path.split(self.textpath)
        files = []
        prefix = baseName + "."
        filePaths = glob.glob(os.path.join(dirName, "%s*" % prefix))
        fileNames = [os.path.split(f)[1] for f in filePaths]
        plen = len(prefix)
        t_set = set()
        for fileName in fileNames:
            suffix = fileName[plen:]
            if self.extMatch.match(suffix):
                s = suffix.split(".")
                t = s[1] if suffix.startswith("cbl") else s[0]
                t_set.add(t)
                files.append({'time': t, 'file': os.path.join(dirName,
                                                              fileName)})

        t_list = list(t_set)
        t_list.sort()
        result = [f['file'] for f in files if
                  f['time'] in t_list[:-(self.backupCount - 1)]]
        return result

    def initSizeRollingCount(self):
        """
        Init the max number of log files for current time.
        """
        dirName, baseName = os.path.split(self.textpath)
        prefix = baseName + "."
        filePaths = glob.glob(os.path.join(dirName, "%s*" % prefix))
        fileNames = [os.path.split(f)[1] for f in filePaths]
        plen = len(prefix)
        for fileName in fileNames:
            suffix = fileName[plen:]
            try:
                self.sizeRollingCount = max(self.sizeRollingCount, int(suffix))
            except ValueError:
                pass

    def _sizeRoll(self):
        self.close()
        for i in range(self.backupCount - 1, 0, -1):
            sbfn = "%s.%d" % (self.binpath, i)
            dbfn = "%s.%d" % (self.binpath, i + 1)
            stfn = "%s.%d" % (self.textpath, i)
            dtfn = "%s.%d" % (self.textpath, i + 1)
            if os.path.exists(sbfn):
                if os.path.exists(dbfn):
                    os.remove(dbfn)
                os.rename(sbfn, dbfn)
            if os.path.exists(stfn):
                if os.path.exists(dtfn):
                    os.remove(dtfn)
                os.rename(stfn, dtfn)
        dbfn = self.binpath + ".1"
        dtfn = self.textpath + ".1"
        if os.path.exists(dbfn):
            os.remove(dbfn)
        if os.path.exists(dtfn):
            os.remove(dtfn)
        if os.path.exists(self.binpath):
            os.rename(self.binpath, dbfn)
        if os.path.exists(self.textpath):
            os.rename(self.textpath, dtfn)
        self._deleteFilesForSizeRolling()
        return dbfn, dtfn

    def _deleteFilesForSizeRolling(self):
        for i in range(self.sizeRollingCount, self.backupCount -1, -1):
            dbfn = "%s.%d" % (self.binpath, i)
            dtfn = "%s.%d" % (self.textpath, i)
            if os.path.exists(dbfn):
                os.remove(dbfn)
            if os.path.exists(dtfn):
                os.remove(dtfn)

    def _timeRoll(self):
        self.close()
        # get the time that this sequence started at and make it a TimeTuple
        currentTime = int(time.time())
        dstNow = time.localtime(currentTime)[-1]
        t = self.rolloverAt - self.interval
        if self.utc:
            timeTuple = time.gmtime(t)
        else:
            timeTuple = time.localtime(t)
            dstThen = timeTuple[-1]
            if dstNow != dstThen:
                if dstNow:
                    addend = 3600
                else:
                    addend = -3600
                timeTuple = time.localtime(t + addend)

        for i in range(self.backupCount - 1, 0, -1):
            sbfn = "%s.%d" % ( self.binpath, i)
            dbfn = "%s.%s.%d" % (
            self.binpath, time.strftime(self.suffix, timeTuple),i)
            stfn = "%s.%d" % (self.textpath, i)
            dtfn = "%s.%s.%d" % (
            self.textpath, time.strftime(self.suffix, timeTuple), i)
            if os.path.exists(sbfn):
                if os.path.exists(dbfn):
                    os.remove(dbfn)
                os.rename(sbfn, dbfn)
            if os.path.exists(stfn):
                if os.path.exists(dtfn):
                    os.remove(dtfn)
                os.rename(stfn, dtfn)

        dbfn = self.binpath + "." + time.strftime(self.suffix, timeTuple)
        odbfn = dbfn
        dtfn = self.textpath + "." + time.strftime(self.suffix, timeTuple)
        odtfn = dtfn
        append=1
        while os.path.exists(dbfn):
            dbfn = odbfn + '.{0}'.format(append)
            append += 1
        append=1
        while os.path.exists(dtfn):
            dtfn = odtfn + '.{0}'.format(append)
            append += 1
        if os.path.exists(self.binpath):
            os.rename(self.binpath, dbfn)
        if os.path.exists(self.textpath):
            os.rename(self.textpath, dtfn)
        if self.backupCount > 0:
            for s in self.getFilesToDelete():
                os.remove(s)

        newRolloverAt = self.computeRollover(currentTime)
        while newRolloverAt <= currentTime:
            newRolloverAt = newRolloverAt + self.interval
        #If DST changes and midnight or weekly rollover, adjust for this.
        if (self.when == 'MIDNIGHT' or self.when.startswith('W')) and not self.utc:
            dstAtRollover = time.localtime(newRolloverAt)[-1]
            if dstNow != dstAtRollover:
                if not dstNow:  # DST kicks in before next rollover, so we need to deduct an hour
                    addend = -3600
                else:           # DST bows out before next rollover, so we need to add an hour
                    addend = 3600
                newRolloverAt += addend
        self.rolloverAt = newRolloverAt
        return dbfn, dtfn

    def doRollover(self, rolling_type):
        """
        do a rollover based on the rolling type.
        """
        if rolling_type == RollingTypes.size_rolling:
            return self._sizeRoll()
        if rolling_type == RollingTypes.time_rolling:
            return self._timeRoll()


class Logger(object):
    """
    :param console:  If true, [] will be used to denote non-text events.  If
                     False, events will be formatted like syslog:
                     date: message<CR>
    """
    def __new__(cls, logname, console=False, tenant=None, buffered=True):
        global _loggers
        if console:
            relpath = 'consoles/' + logname
        else:
            relpath = logname
        if relpath in _loggers:
            return _loggers[relpath]
        else:
            return object.__new__(cls)

    def __init__(self, logname, console=False, tenant=None, buffered=True):
        if hasattr(self, 'initialized'):
            # we are just a copy of the same object
            return
        self.initialized = True
        self.buffered = buffered
        self.filepath = confluent.config.configmanager.get_global("logdirectory")
        if self.filepath is None:
            if os.name == 'nt':
                self.filepath = os.path.join(
                    os.getenv('SystemDrive'), '\\ProgramData', 'confluent',
                    'logs')
            else:
                self.filepath = "/var/log/confluent"
        self.isconsole = console
        if console:
            self.filepath = os.path.join(self.filepath, "consoles")
        if not os.path.isdir(self.filepath):
            os.makedirs(self.filepath, 448)
        self.writer = None
        self.closer = None
        self.handler = TimedAndSizeRotatingFileHandler(self.filepath, logname,
                                                       interval=1)
        self.lockfile = None
        self.logname = logname
        self.logentries = collections.deque()

    def writedata(self):
        while self.logentries:
            textfile, binfile = self.handler.open()
            entry = self.logentries.popleft()
            ltype = entry[0]
            tstamp = entry[1]
            data = entry[2]
            evtdata = entry[3]
            if len(data) > 65535:
                # our max log entry is 65k, take only the first 65k and put
                # rest back on as a continuation
                entry[2] = data[65535:]
                self.logentries.appendleft(entry)
                data = data[:65535]
            textdate = ''
            if self.isconsole and ltype != 2:
                textdate = time.strftime(
                    '[%m/%d %H:%M:%S ', time.localtime(tstamp))
                if ltype == DataTypes.event and evtdata in Events.logstr:
                    textdate += Events.logstr[evtdata]
            elif not self.isconsole:
                textdate = time.strftime(
                    '%b %d %H:%M:%S ', time.localtime(tstamp))
            flock(textfile, LOCK_EX)
            try:
                offset = textfile.tell() + len(textdate)
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
                        if not isinstance(textdate, bytes):
                            textdate = textdate.encode('utf-8')
                        if not isinstance(data, bytes):
                            data = data.encode('utf-8')
                        textrecord = textdate + data + b']'
                else:
                    textrecord = textdate + data
                    if not textrecord.endswith('\n'):
                        textrecord += '\n'
                files = self.handler.try_emit(binrecord, textrecord)
            except struct.error:
                files = self.handler.doRollover(RollingTypes.size_rolling)
            finally:
                try:
                    flock(textfile, LOCK_UN)
                except Exception:
                    pass
            if not files:
                self.handler.emit(binrecord, textrecord)
            else:
                # Log the rolling event at first, then log the last data
                # which cause the rolling event.
                to_bfile, to_tfile = files
                self.logentries.appendleft(entry)
                roll_data = json.dumps({'previouslogfile': to_tfile})
                self.logentries.appendleft([DataTypes.event, tstamp, roll_data,
                                            Events.logrollover, None])
        if self.closer is None:
            self.closer = spawn_after(15, self.closelog)
        self.writer = None

    def read_recent_text(self, size):

        def parse_last_rolling_files(textfile, offset, datalen):
            textfile.seek(offset, 0)
            textpath = json.loads(textfile.read(datalen))['previouslogfile']
            dir_name, base_name = os.path.split(textpath)
            temp = base_name.split('.')
            temp.insert(1,'cbl')
            # find the recent bin file
            binpath = os.path.join(dir_name, ".".join(temp))
            return textpath, binpath

        textpath = self.handler.textpath
        binpath = self.handler.binpath
        try:
            textfile = open(textpath, mode='r')
            binfile = open(binpath, mode='r')
        except IOError:
            return '', 0, 0
        flock(binfile, LOCK_SH)
        binfile.seek(0, 2)
        binidx = binfile.tell()
        currsize = 0
        offsets = []
        termstate = None
        recenttimestamp = 0
        flock(textfile, LOCK_SH)
        while binidx > 0 and currsize < size:
            binidx -= 16
            binfile.seek(binidx, 0)
            recbytes = binfile.read(16)
            (_, ltype, offset, datalen, tstamp, evtdata, eventaux, _) = \
                struct.unpack(">BBIHIBBH", recbytes)
            # rolling events found.
            if ltype == DataTypes.event and evtdata == Events.logrollover:
                txtpath, bpath = parse_last_rolling_files(textfile, offset,
                                                          datalen)
                if txtpath == textpath:
                    break
                if bpath == binpath:
                    break
                textpath = txtpath
                binpath = bpath
                # Rolling event detected, close the current bin file, then open
                # the renamed bin file.
                flock(binfile, LOCK_UN)
                flock(textfile, LOCK_UN)
                binfile.close()
                textfile.close()
                try:
                    binfile = open(binpath, mode='r')
                    textfile = open(textpath, mode='r')
                except IOError:
                    binfile = None
                    textfile = None
                    break
                flock(binfile, LOCK_SH)
                flock(textfile, LOCK_SH)
                binfile.seek(0, 2)
                binidx = binfile.tell()
                # things have been set up for next iteration to dig to
                # previous log file, go to next iteration
                continue
            elif ltype != 2:
                continue
            if tstamp > recenttimestamp:
                recenttimestamp = tstamp
            currsize += datalen
            offsets.append((offset, datalen, textpath))
            if termstate is None:
                termstate = eventaux
        try:
            flock(binfile, LOCK_UN)
            binfile.close()
        except:
            pass
        textdata = ''
        while offsets:
            (offset, length, textpath) = offsets.pop()
            if textfile is None:
                textfile = open(textpath, mode='r')
                flock(textfile, LOCK_SH)
            if textfile.name != textpath:
                try:
                    flock(textfile, LOCK_UN)
                    textfile.close()
                    textfile = open(textpath, mode='r')
                    flock(textfile, LOCK_SH)
                except (ValueError, IOError) as e:
                    break
            try:
                textfile.seek(offset, 0)
            except ValueError:
                # file was closed, settle with what we have and continue
                break
            textdata += textfile.read(length)
        try:
            flock(textfile, LOCK_UN)
            textfile.close()
        except:
            pass
        if termstate is None:
            termstate = 0
        return textdata, termstate, recenttimestamp

    def write(self, data):
        """Write plain text to log

        This is intended so that a log object may be used to replace a
        normal file object with a loss of capability.  For example,
        sys.stdout = logobject

        :param data: data to log
        """
        if data != '\n':  # 'print' likes to do '\n' by itself, skip that
            self.log(traceback.format_stack(limit=2)[0][:-1] + ": " + data)

    def flush(self):
        pass

    def log(self, logdata=None, ltype=None, event=0, eventdata=None):
        if type(logdata) not in (bytes, unicode, dict):
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
        if self.buffered:
            if self.writer is None:
                self.writer = spawn_after(2, self.writedata)
        else:
            self.writedata()

    def closelog(self):
        self.handler.close()
        self.closer = None

globaleventlog = None
tracelog = None


def log(logdata=None, ltype=None, event=0, eventdata=None, flush=False):
    global globaleventlog
    if globaleventlog is None:
        globaleventlog = Logger('events')
    globaleventlog.log(logdata, ltype, event, eventdata)
    if flush:
        globaleventlog.writedata()

def logtrace():
    global tracelog
    if tracelog is None:
        tracelog = Logger('trace', buffered=False)
    tracelog.log(traceback.format_exc(), ltype=DataTypes.event,
                 event=Events.stacktrace)
