# Copyright 2017 Lenovo
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

import fcntl
import sys
import struct
import termios

def get_screengeom():
    # returns height in cells, width in cells, width in pixels, height in pixels
    return struct.unpack('hhhh', fcntl.ioctl(sys.stdout, termios.TIOCGWINSZ,
                                           b'........'))
class ScreenPrinter(object):

    def __init__(self, noderange, client, textlen=4):
        self.squeeze = sys.stdout.isatty()
        self.textlen = textlen
        self.noderange = noderange
        self.client = client
        self.nodeoutput = {}
        self.nodelist = []
        self.nodepos = {}
        self.lastrows = 0
        self.fieldchanged = False
        maxlen = 0
        for ans in self.client.read('/noderange/{0}/nodes/'.format(noderange)):
            if 'error' in ans:
                sys.stderr.write(ans['error'])
                continue
            nodename = ans['item']['href'][:-1]
            if len(nodename) > maxlen:
                maxlen = len(nodename)
            self.nodelist.append(nodename)
            self.nodeoutput[nodename] = ''
        self.nodenamelen = maxlen
        self.textlen = textlen
        self.fieldwidth = maxlen + textlen + 1  # 1 for column

    def set_output(self, node, text):
        if self.nodeoutput.get(node, None) == text:
            return
        self.nodeoutput[node] = text
        if len(text) >= self.textlen:
            self.textlen = len(text) + 1
            self.fieldwidth = self.textlen + self.nodenamelen + 1
            self.fieldchanged = True
        self.drawscreen(node)

    def drawscreen(self, node=None):
        if self.squeeze:
            currheight, currwidth, _, _ = get_screengeom()
            currheight -= 2
            if currheight < 1:
                currheight = 1
            numfields = currwidth // self.fieldwidth
            fieldformat = '{{0:>{0}}}:{{1:{1}}}'.format(self.nodenamelen,
                                                        self.textlen)
            #sys.stdout.write('\x1b[2J\x1b[;H')  # clear screen
            if len(self.nodelist) < (numfields * currheight):
                numfields = len(self.nodelist) // currheight + 1
        else:
            numfields = 1
            fieldformat = '{0}: {1}'
        if self.squeeze:
            columns = [self.nodelist[x:x+currheight] for x in range(0, len(self.nodelist), currheight)]
            if self.lastrows:
                sys.stdout.write('\x1b[{0}A'.format(self.lastrows))
            if node and self.lastrows == len(columns[0]) and not self.fieldchanged:
                targline, targcol = self.nodepos[node]
                if targline:
                    sys.stdout.write('\x1b[{0}B'.format(targline))
                if targcol:
                    sys.stdout.write('\x1b[{0}C'.format(targcol))
                sys.stdout.write(fieldformat.format(node, self.nodeoutput[node]))
                sys.stdout.write('\r\x1b[{0}B'.format(self.lastrows - targline))
            else:
                self.lastrows = 0
                self.fieldchanged = False
                column = 0
                for currow in range(0, len(columns[0])):
                    sys.stdout.write('\x1b[2K')
                    for col in columns:
                        try:
                            node = col[currow]
                            self.nodepos[node] = (currow, column)
                            sys.stdout.write(fieldformat.format(node, self.nodeoutput[node]))
                            column += len(fieldformat.format(node, self.nodeoutput[node]))
                        except IndexError:
                            break
                    sys.stdout.write('\n')
                    column = 0
                    self.lastrows += 1
                sys.stdout.write('\x1b[J')
        else:
            if node:
                nodes = [node]
            else:
                nodes = self.nodelist
            for node in nodes:
                sys.stdout.write(fieldformat.format(node, self.nodeoutput[node]))
                sys.stdout.write('\n')
        sys.stdout.flush()





if __name__ == '__main__':
    import confluent.client as client
    c = client.Command()
    p = ScreenPrinter('d1-d12', c)
    p.set_output('d3', 'Upload: 67%')
    p.set_output('d7', 'Upload: 67%')



