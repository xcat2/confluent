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
    record = binf.read(16)
    oldtcattr = termios.tcgetattr(sys.stdin.fileno())
    tty.setraw(sys.stdin.fileno())
    currfl = fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL)
    fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, currfl | os.O_NONBLOCK)
    recordcount = 1
    while record:
        showrecords(record, txtf, binf, recordcount)
        recordcount = 1
        select.select((sys.stdin,), (), (), 86400)
        myinput = sys.stdin.read()
        if myinput == '\x1b[C':  # right
            record = binf.read(16)
        elif myinput == '\x1b[D':  # left
            sys.stdout.write('\x1b[2J\x1b[;H')
            numrecords = 0
            prevoffset = 1
            while numrecords < 16 and prevoffset > 0:
                prevoffset = binf.tell() - 32
                if prevoffset < 0:
                    prevoffset = 0
                binf.seek(prevoffset)
                record = binf.read(16)
                while record[1] != '\x02' and prevoffset > 0:
                    prevoffset = binf.tell() - 32
                    if prevoffset < 0:
                        prevoffset = 0
                    binf.seek(prevoffset)
                    record = binf.read(16)
                if record[1] == '\x02':
                    numrecords += 1
            recordcount = numrecords
        elif myinput.lower() == 'q':
            break
        else:
            record = binf.read(16)
    currfl = fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL)
    fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, currfl ^ os.O_NONBLOCK)
    termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, oldtcattr)
    sys.stdout.write('\x1b[m')

def showrecords(record, txtf, binf, recordcount):
    while record and recordcount:
        recs = struct.unpack('!BBIHIBBH', record)
        offset = recs[2]
        size = recs[3]
        tstamp = recs[4]
        if recs[1] == 2:
            tstamp = time.strftime('%m/%d %H:%M:%S ', time.localtime(tstamp))
            txtf.seek(offset)
            currdata = txtf.read(size)
            sys.stdout.write(currdata)
            sys.stdout.write('\x1b]0;{0}\x07'.format(tstamp))
            sys.stdout.flush()
            recordcount -= 1
            if recordcount:
                record = binf.read(16)
        else:
            record = binf.read(16)



    
if __name__ == '__main__':
    binfile = sys.argv[1]
    txtfile = sys.argv[2]
    main(binfile, txtfile)

