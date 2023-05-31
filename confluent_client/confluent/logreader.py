#!/usr/bin/python3
import collections
import os
import struct
import sys
import time
import fcntl
import select
import termios
import tty

def writeout(data):
    if isinstance(data, str) and not isinstance(data, bytes):
        data = data.encode('utf8')
    try:
        if hasattr(sys.stdout, 'buffer'):
            sys.stdout.buffer.write(data)
        else:
            sys.stdout.write(data)
    except IOError:
        time.sleep(0.1)
        pass


class LogReplay(object):
    def __init__(self, logfile, cblfile):
        self.bin = open(cblfile, 'rb')
        self.txt = open(logfile, 'rb')
        self.cleardata = []
        self.clearidx = 0
        self.pendingdata = collections.deque([])
        self.priordata = collections.deque([])
        self.laststamp = None
        self.needclear = False
        self.lasttxt = ''

    def _rewind(self, datasize=None):
        curroffset = self.bin.tell() - 16
        if self.cleardata and self.clearidx > 1:
            self.clearidx -= 1
            priordata = self.cleardata[self.clearidx - 1]
            return curroffset, priordata
        self.cleardata = []
        self.clearidx = 0
        newoffset = curroffset - 32
        if newoffset < 0:  #TODO: Follow a log roll
            newoffset = 0
        if datasize:
            while datasize > 0 and newoffset > 0:
                self.bin.seek(newoffset)
                tmprec = self.bin.read(16)
                newoffset -= 32
                tmprec = struct.unpack('!BBIHIBBH', tmprec)
                if tmprec[1] == 2:
                    datasize -= tmprec[3]
        if newoffset >= 0:
            self.bin.seek(newoffset)
        return curroffset, None

    def debuginfo(self):
        return '{0}, {1}'.format(self.bin.tell(), self.clearidx)

    def get_output(self, reverse=False):
        endoffset = None
        output = b''
        if reverse:  # Forget the uncommited future, if present
            output += b'\x1b[2J\x1b[H'
            endoffset, priordata = self._rewind(4096)
            if priordata is not None:
                return priordata, 1
        elif self.needclear:
            output += b'\x1b[2J\x1b[H'
            self.needclear = False
        if self.cleardata and self.clearidx < len(self.cleardata):
            datachunk = self.cleardata[self.clearidx]
            self.clearidx += 1
            return datachunk, 1
        self.cleardata = []
        self.clearidx = 0
        while (not reverse) or (self.bin.tell() < endoffset):
            record = self.bin.read(16)
            if not record:
                return b'', 0
            record = struct.unpack('!BBIHIBBH', record)
            if record[0] > 16:
                # Unsupported record, skip
                self.bin.seek(record[0] - 16, 1)
                continue
            type = record[1]
            offset = record[2]
            size = record[3]
            evtdata = record[5]
            auxdata = record[6]
            if type == 3:
                #TODO: provide data for status bar
                continue
            elif type == 2:
                self.laststamp = record[4]
                self.txt.seek(offset)
                txtout = self.txt.read(size)
                if reverse and self.bin.tell() < endoffset:
                    output += txtout
                    continue
                self.paginate(txtout)
                if self.cleardata:
                    self.clearidx = 0
                    if not self.cleardata[0]:
                        self.cleardata = self.cleardata[1:]
                    if self.cleardata:
                        if reverse:
                            output = self.cleardata[-1]
                            self.clearidx = len(self.cleardata)
                        else:
                            output += self.cleardata[0]
                            self.clearidx = 1
                else:
                    output += txtout
                break
        if endoffset is not None and endoffset >= 0:
            self.bin.seek(endoffset)
        self.lasttxt = output
        return output, 1

    def paginate(self, txtout):
        cleardata = [txtout]
        nextcleardata = []
        for sep in (b'\x1b[2J', b'\x1b[H\x1b[J'):
            replacementcleardata = []
            for txtout in cleardata:
                nextcleardata = txtout.split(sep)
                if len(nextcleardata) > 1:
                    for idx in range(1, len(nextcleardata)):
                        nextcleardata[idx] = sep + nextcleardata[idx]
                replacementcleardata.extend(nextcleardata)
                nextcleardata = []
            cleardata = replacementcleardata
        if len(cleardata) > 1:
            self.cleardata = cleardata
        return

    def begin(self):
        self.needclear = True
        self.bin.seek(0)

    def end(self):
        self.bin.seek(0, 2)

    def search(self, searchstr, skipfirst=False):
        overlap = len(searchstr)
        firstoffset = self.bin.tell()
        lastoffset = firstoffset
        output = self.lasttxt
        while searchstr not in output:
            output, delay = self.get_output()
            if not self.cleardata and lastoffset == self.bin.tell():
                self.bin.seek(firstoffset)
                return b'', 0
            lastoffset = self.bin.tell()
        if skipfirst:
            output, delay = self.get_output()
            while searchstr not in output:
                output, delay = self.get_output()
                if not self.cleardata and lastoffset == self.bin.tell():
                    self.bin.seek(firstoffset)
                    return b'', 0
                lastoffset = self.bin.tell()
        clear = b'\x1b[2J\x1b[H'
        txtchunks = self.lasttxt.split(searchstr)
        output = clear + txtchunks[0]
        txtchunks = txtchunks[1:]
        while txtchunks:
            output += b'\x1b[7m' + searchstr + b'\x1b[27m' + txtchunks[0]
            txtchunks = txtchunks[1:]
        return output, 0


def _replay_to_console(txtfile, binfile):
    replay = LogReplay(txtfile, binfile)
    oldtcattr = termios.tcgetattr(sys.stdin.fileno())
    tty.setraw(sys.stdin.fileno())
    currfl = fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL)
    fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, currfl | os.O_NONBLOCK)
    reverse = False
    skipnext = False
    quitit = False
    searchstr = None
    writeout('\x1b[2J\x1b[;H')
    prepend = ''
    try:
        while not quitit:
            if not skipnext:
                newdata, delay = replay.get_output(reverse)
            skipnext = False
            reverse = False
            if newdata:
                if prepend:
                    newdata = prepend + newdata
                    prepend = b''
                writeout(newdata)
                newdata = ''
                writeout('\x1b]0;[Time: {0}]\x07'.format(
                    time.strftime('%m/%d %H:%M:%S', time.localtime(replay.laststamp))))
                try:
                    if hasattr(sys.stdout, 'buffer'):
                        sys.stdout.buffer.flush()
                    else:
                        sys.stdout.flush()
                except IOError:
                    pass
            while True:
                select.select((sys.stdin,), (), (), 86400)
                myinput = sys.stdin.read()
                if myinput.startswith('\x1b[C') or myinput.startswith('\x1bOC') or myinput == '\r':  # right
                    break
                elif myinput.startswith('\x1b[D') or myinput.startswith('\x1bOD') or myinput == 'y':  # left
                    writeout('\x1b[2J\x1b[;H')
                    reverse = True
                    break
                elif myinput == 'G' or myinput.startswith('\x1b[F'):
                    replay.end()
                    reverse = True
                    break
                elif myinput == 'g' or myinput.startswith('\x1b[H'):
                    replay.begin()
                    break
                elif myinput.lower() == 'q' or myinput == '\x03':
                    quitit = True
                    break
                elif myinput.lower() == 'd':
                    writeout('\x1b];{0}\x07'.format(replay.debuginfo()))
                    if hasattr(sys.stdout, 'buffer'):
                        sys.stdout.buffer.flush()
                    else:
                        sys.stdout.flush()
                elif myinput.lower() == '/':
                    sys.stdout.write('\x1b7\x1b[99999;0H\x1b[2K')
                    searchstr = ''
                    nxtchr = '/'
                    while '\r' not in searchstr:
                        sys.stdout.write(nxtchr)
                        sys.stdout.flush()
                        select.select((sys.stdin,), (), (), 86400)
                        nxtchr = sys.stdin.read(1)
                        if nxtchr in ('\x08', '\x7f'):
                            searchstr = searchstr[:-1]
                            nxtchr = '\x08 \x08'
                        else:
                            searchstr += nxtchr
                    if not isinstance(searchstr, bytes):
                        searchstr = searchstr.encode('utf8')
                    searchstr = searchstr[:-1]
                    newdata, delay = replay.search(searchstr)
                    if not newdata:
                        sys.stdout.write('\x1b[1K\rNo match found')
                        prepend = b'\x1b[1K\x1b8'
                    else:
                        sys.stdout.write('\x1b[1K\x1b8')
                    sys.stdout.flush()
                    skipnext = True
                    break
                elif myinput.lower() == 'n' and searchstr:
                    newdata, delay = replay.search(searchstr, True)
                    if not newdata:
                        sys.stdout.write('\x1b7\x1b[99999;0H\x1b[2KNo more matches found')
                        sys.stdout.flush()
                        prepend = b'\x1b[1K\x1b8'
                    skipnext = True
                    break
                else:
                    pass # print(repr(myinput))
    except Exception:
        currfl = fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL)
        fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, currfl ^ os.O_NONBLOCK)
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, oldtcattr)
        writeout('\x1b[m\x1b[?25h\n')
        raise
    currfl = fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL)
    fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, currfl ^ os.O_NONBLOCK)
    termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, oldtcattr)
    writeout('\x1b[m\x1b[?25h\n')

def replay_to_console(txtfile):
    if os.path.exists(txtfile + '.cbl'):
        binfile = txtfile + '.cbl'
    elif '.' not in txtfile:
        if '/' not in txtfile:
            txtfile = os.getcwd() + '/' + txtfile
        sys.stderr.write('Unable to locate cbl file: "{0}"\n'.format(txtfile + '.cbl'))
        sys.exit(1)
    else:
        fileparts = txtfile.split('.')
        prefix = '.'.join(fileparts[:-1])
        binfile = prefix + '.cbl.' + fileparts[-1]
        if not os.path.exists(binfile):
            sys.stderr.write('Unable to locate cbl file: "{0}"\n'.format(binfile))
            sys.exit(1)
    _replay_to_console(txtfile, binfile)

def dump_to_console(txtfile):
    if os.path.exists(txtfile + '.cbl'):
        binfile = txtfile + '.cbl'
    elif '.' not in txtfile:
        if '/' not in txtfile:
            txtfile = os.getcwd() + '/' + txtfile
        sys.stderr.write('Unable to locate cbl file: "{0}"\n'.format(txtfile + '.cbl'))
        sys.exit(1)
    else:
        fileparts = txtfile.split('.')
        prefix = '.'.join(fileparts[:-1])
        binfile = prefix + '.cbl.' + fileparts[-1]
        if not os.path.exists(binfile):
            sys.stderr.write('Unable to locate cbl file: "{0}"\n'.format(binfile))
            sys.exit(1)
    replay = LogReplay(txtfile, binfile)
    quitit = False
    writeout('\x1b[2J\x1b[;H')
    prepend = ''
    try:
        while not quitit:
            newdata, delay = replay.get_output(False)
            if newdata:
                if prepend:
                    newdata = prepend + newdata
                    prepend = b''
                writeout(newdata.replace(b'\r\n', '\r\n[ {0} ] '.format(time.strftime('%m/%d %H:%M:%S', time.localtime(replay.laststamp))).encode('utf8')))
                newdata = ''
                try:
                    if hasattr(sys.stdout, 'buffer'):
                        sys.stdout.buffer.flush()
                    else:
                        sys.stdout.flush()
                except IOError:
                    pass
            else:
                break
    except Exception:
        writeout('\x1b[m\x1b[?25h\n')
        raise
    writeout('\x1b[m\x1b[?25h\n')

if __name__ == '__main__':
    replay_to_console(sys.argv[1])
