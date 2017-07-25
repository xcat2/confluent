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

import difflib
import sys

try:
    range = xrange
except NameError:
    pass


def _colorize_line(orig, mask):
    highlighted = False
    newline = orig[0]
    for i in range(1, len(orig)):
        if i > len(mask) - 1:
            if highlighted:
                newline += '\x1b[0m'
            newline += orig[i:]
            break
        if highlighted and mask[i] == ' ':
            highlighted = False
            newline += '\x1b[0m'
        elif not highlighted and mask[i] != ' ':
            highlighted = True
            newline += '\x1b[31m'
        newline += orig[i]
    newline += '\x1b[0m'
    return newline


def colordiff(first, second):
    diffdata = list(difflib.ndiff(first, second))
    for i in range(len(diffdata)):
        if i < len(diffdata) - 1 and diffdata[i + 1].startswith('?'):
            yield _colorize_line(diffdata[i], diffdata[i + 1])
        elif diffdata[i].startswith('?'):
            continue
        else:
            yield diffdata[i]


class GroupedData(object):

    def __init__(self):
        self.bynode = {}
        self.byoutput = {}

    def generate_byoutput(self):
        self.byoutput = {}
        for n in self.bynode:
            output = '\n'.join(self.bynode[n])
            if output not in self.byoutput:
                self.byoutput[output] = set([n])
            else:
                self.byoutput[output].add(n)

    def add_line(self, node, line):
        if node not in self.bynode:
            self.bynode[node] = [line]
        else:
            self.bynode[node].append(line)

    def print_deviants(self, output=sys.stdout, skipmodal=True):
        self.generate_byoutput()
        modaloutput = None
        ismodal = True
        for outdata in reversed(
                sorted(self.byoutput, key=lambda x: len(self.byoutput[x]))):
            if modaloutput is None:
                modaloutput = outdata
            if skipmodal:
                skipmodal = False
                ismodal = False
                continue
            output.write('====================================\n')
            output.write(','.join(sorted(self.byoutput[outdata])))
            output.write('\n====================================\n')
            if ismodal:
                ismodal = False
                output.write(outdata)
            else:
                output.write('\n'.join(colordiff(modaloutput.split('\n'),
                                                 outdata.split('\n'))))
            output.write('\n\n')
        output.flush()

if __name__ == '__main__':
    groupoutput = GroupedData()
    for line in sys.stdin.read().split('\n'):
        if not line:
            continue
        groupoutput.add_line(*line.split(': ', 1))
    groupoutput.print_deviants()