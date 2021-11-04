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
    done = False
    if isinstance(data, str) and not isinstance(data, bytes):
        data = data.encode('utf8')
    try:
        sys.stdout.buffer.write(data)
        done = True
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
                if b'\x1b[2J' in txtout:
                    self.cleardata = txtout.split(b'\x1b[2J')
                    for idx in range(1, len(self.cleardata)):
                        self.cleardata[idx] = b'\x1b[2J' + self.cleardata[idx]
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
        return output, 1

    def begin(self):
        self.needclear = True
        self.bin.seek(0)

    def end(self):
        self.bin.seek(0, 2)


def main(txtfile, binfile):
    replay = LogReplay(txtfile, binfile)
    oldtcattr = termios.tcgetattr(sys.stdin.fileno())
    tty.setraw(sys.stdin.fileno())
    currfl = fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL)
    fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, currfl | os.O_NONBLOCK)
    reverse = False
    skipnext = False
    quitit = False
    writeout('\x1b[2J\x1b[;H')
    try:
        while not quitit:
            if not skipnext:
                newdata, delay = replay.get_output(reverse)
            skipnext = False
            reverse = False
            if newdata:
                writeout(newdata)
                writeout('\x1b]0;[Time: {0}]\x07'.format(
                    time.strftime('%m/%d %H:%M:%S', time.localtime(replay.laststamp))))
                try:
                    sys.stdout.buffer.flush()
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
                    sys.stdout.flush()
                else:
                    pass # print(repr(myinput))
    except Exception:
        currfl = fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL)
        fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, currfl ^ os.O_NONBLOCK)
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, oldtcattr)
        writeout('\x1b[m')
        raise
    currfl = fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL)
    fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, currfl ^ os.O_NONBLOCK)
    termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, oldtcattr)
    writeout('\x1b[m')

if __name__ == '__main__':
    txtfile = sys.argv[1]
    if len(sys.argv) > 2:
        binfile = sys.argv[2]
    else:
        if os.path.exists(txtfile + '.cbl'):
            binfile = txtfile + '.cbl'
        else:
            fileparts = txtfile.split('.')
            prefix = '.'.join(fileparts[:-1])
            binfile = prefix + '.cbl.' + fileparts[-1]
            if not os.path.exists(binfile):
                sys.stderr.write('Unable to locate cbl file\n')
                sys.exit(1)
    main(txtfile, binfile)
