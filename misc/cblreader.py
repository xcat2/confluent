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

def main(binfile, txtfile):
    binf = open(binfile, 'r')
    txtf = open(txtfile, 'r')
    records = collections.deque([])
    records.append(get_next_text_record(binf))
    oldtcattr = termios.tcgetattr(sys.stdin.fileno())
    tty.setraw(sys.stdin.fileno())
    currfl = fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL)
    fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, currfl | os.O_NONBLOCK)
    while True:
        newdata = showrecords(records, txtf, binf)
        select.select((sys.stdin,), (), (), 86400)
        myinput = sys.stdin.read()
        if myinput == '\x1b[C':  # right
            if newdata:
                sys.stdout.write(newdata)
                newdata = ''
            if not records:
                records.append(get_next_text_record(binf))
        elif myinput == '\x1b[D':  # left
            sys.stdout.write('\x1b[2J\x1b[;H')
            prevoffset = 1
            restoreoffset = binf.tell() - 16
            while len(records) < 16 and prevoffset > 0:
                prevoffset = binf.tell() - 32
                if prevoffset < 0:
                    prevoffset = 0
                binf.seek(prevoffset)
                record = binf.read(16)
                if not record:
                    break
                while record[1] != '\x02' and prevoffset > 0:
                    prevoffset = binf.tell() - 32
                    if prevoffset < 0:
                        prevoffset = 0
                    binf.seek(prevoffset)
                    record = binf.read(16)
                if record[1] == '\x02':
                    records.appendleft(record)
                else:
                    records.appendleft(get_next_text_record(binf))
            binf.seek(restoreoffset if restoreoffset > 0 else 0)
        elif myinput.lower() == 'q':
            break
        elif myinput.lower() == 'd':
            print(repr(records))
            print(repr(binf.tell()))
        else:
            records.append(get_next_text_record(binf))
    currfl = fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL)
    fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, currfl ^ os.O_NONBLOCK)
    termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, oldtcattr)
    sys.stdout.write('\x1b[m')

def get_next_text_record(binf):
    record = binf.read(16)
    while record and record[1] != '\x02':
        record = binf.read(16)
    return record


def showrecords(records, txtf, binf):
    extradata = ''
    while records and records[0] and not extradata:
        record = records.popleft()
        recs = struct.unpack('!BBIHIBBH', record)
        offset = recs[2]
        size = recs[3]
        tstamp = recs[4]
        if recs[1] == 2:
            tstamp = time.strftime('%m/%d %H:%M:%S ', time.localtime(tstamp))
            txtf.seek(offset)
            currdata = txtf.read(size)
            if not records and not currdata.startswith('\x1b[2J') and '\x1b[2J' in currdata:
                currdata, extradata = currdata.split('\x1b[2J', 1)
                extradata = '\x1b[2J' + extradata
            sys.stdout.write(currdata)
            sys.stdout.write('\x1b]0;{0}\x07'.format(tstamp))
            sys.stdout.flush()
    return extradata



    
if __name__ == '__main__':
    binfile = sys.argv[1]
    txtfile = sys.argv[2]
    main(binfile, txtfile)

