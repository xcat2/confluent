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
    while not done:
        try:
            sys.stdout.write(data)
            done = True
        except IOError:
            pass


class LogReplay(object):
    def __init__(self, logfile, cblfile):
        self.bin = open(cblfile, 'r')
        self.txt = open(logfile, 'r')
        self.cleardata = []
        self.clearidx = 0
        self.pendingdata = collections.deque([])
        self.priordata = collections.deque([])
        self.laststamp = None

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
        output = ''
        if reverse:  # Forget the uncommited future, if present
            output += '\x1b[2J'
            endoffset, priordata = self._rewind(4096)
            if priordata is not None:
                return priordata, 1
        if self.cleardata and self.clearidx < len(self.cleardata):
            datachunk = self.cleardata[self.clearidx]
            self.clearidx += 1
            return datachunk, 1
        self.cleardata = []
        self.clearidx = 0
        while (not reverse) or (self.bin.tell() < endoffset):
            record = self.bin.read(16)
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
                if '\x1b[2J' in txtout:
                    self.cleardata = txtout.split('\x1b[2J')
                    for idx in range(1, len(self.cleardata)):
                        self.cleardata[idx] = '\x1b[2J' + self.cleardata[idx]
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


def main(txtfile, binfile):
    replay = LogReplay(txtfile, binfile)
    oldtcattr = termios.tcgetattr(sys.stdin.fileno())
    tty.setraw(sys.stdin.fileno())
    currfl = fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL)
    fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, currfl | os.O_NONBLOCK)
    reverse = False
    skipnext = False
    writeout('\x1b[2J\x1b[;H')
    try:
        while True:
            if not skipnext:
                newdata, delay = replay.get_output(reverse)
            skipnext = False
            reverse = False
            writeout(newdata)
            writeout('\x1b]0;[Time: {0}]\x07'.format(
                time.strftime('%m/%d %H:%M:%S', time.localtime(replay.laststamp))))
            sys.stdout.flush()
            select.select((sys.stdin,), (), (), 86400)
            myinput = sys.stdin.read()
            if myinput == '\x1b[C':  # right
                continue
            elif myinput == '\x1b[D':  # left
                writeout('\x1b[2J\x1b[;H')
                reverse = True
                continue
            elif myinput.lower() == 'q':
                break
            elif myinput.lower() == 'd':
                writeout('\x1b];{0}\x07'.format(replay.debuginfo()))
                sys.stdout.flush()
                select.select((sys.stdin,), (), (), 3200)
                skipnext = True
            else:
                continue
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
    binfile = sys.argv[2]
    txtfile = sys.argv[1]
    main(txtfile, binfile)

