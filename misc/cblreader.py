import struct
import sys
import time
def main(binfile, txtfile):
    binf = open(binfile, 'r')
    txtf = open(txtfile, 'r')
    record = binf.read(16)
    while record:
        recs = struct.unpack('!BBIHIBBH', record)
        offset = recs[2]
        size = recs[3]
        tstamp = recs[4]
        tstamp = time.strftime('%m/%d %H:%M:%S ', time.localtime(tstamp))
        txtf.seek(offset)
        currdata = txtf.read(size)
        sys.stdout.write(currdata)
        sys.stdout.write('\x1b]0;{0}\x07'.format(tstamp))
        sys.stdout.flush()
        raw_input()
        record = binf.read(16)


    
if __name__ == '__main__':
    binfile = sys.argv[1]
    txtfile = sys.argv[2]
    main(binfile, txtfile)

