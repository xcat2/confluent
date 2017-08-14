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
import re
import sys

try:
    range = xrange
except NameError:
    pass



numregex = re.compile('([0-9]+)')
def humanify_nodename(nodename):
    """Analyzes nodename in a human way to enable natural sort

    :param nodename: The node name to analyze
    :returns: A structure that can be consumed by 'sorted'
    """
    return [int(text) if text.isdigit() else text.lower()
            for text in re.split(numregex, nodename)]


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
    '''A post processor to sort and compare per-node data

    :param confluentconnection: If given, will attempt to use the connection to abbreviate noderanges
    '''

    def __init__(self, confluentconnection=None):
        self.bynode = {}
        self.byoutput = {}
        self.client = confluentconnection

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

    def get_group_text(self, nodes):
        if self.client:
            noderange = ''
            for reply in self.client.create('/noderange//abbreviate', {'nodes': sorted(nodes)}):
                noderange = reply['noderange']
            return noderange
        else:
            return ','.join(sorted(nodes, key=humanify_nodename))

    def print_all(self, output=sys.stdout, skipmodal=False, reverse=False,
                  count=False):
        self.generate_byoutput()
        modaloutput = None
        ismodal = True
        outdatalist = sorted(
            self.byoutput, key=lambda x: len(self.byoutput[x]))
        if not reverse:
             outdatalist = reversed(outdatalist)
        if reverse and skipmodal:
            # if reversed, the last is biggest and should be skipped if modal
            outdatalist = outdatalist[:-1]
        for outdata in outdatalist:
            if not reverse and skipmodal:
                # If big first, this makes skipmodal skip first
                skipmodal = False
                continue
            currout = '====================================\n'
            currout += self.get_group_text(self.byoutput[outdata])
            currout += '\n====================================\n'
            if count:
                currout += 'Count: {0}'.format(len(list(
                    self.byoutput[outdata])))
                currout += '\n====================================\n'
            currout += outdata
            currout += '\n\n'
            output.write(currout)
        output.flush()

    def print_deviants(self, output=sys.stdout, skipmodal=False, reverse=False,
                       count=False):
        self.generate_byoutput()
        modaloutput = None
        ismodal = True
        revoutput = []
        for outdata in reversed(
                sorted(self.byoutput, key=lambda x: len(self.byoutput[x]))):
            if modaloutput is None:
                modaloutput = outdata
            if skipmodal:
                skipmodal = False
                ismodal = False
                continue
            currout = '====================================\n'
            currout += self.get_group_text(self.byoutput[outdata])
            currout += '\n====================================\n'
            if count:
                currout += 'Count: {0}'.format(len(list(
                    self.byoutput[outdata])))
                currout += '\n====================================\n'
            if ismodal:
                ismodal = False
                currout += outdata
            else:
                currout += '\n'.join(colordiff(modaloutput.split('\n'),
                                                 outdata.split('\n')))
            currout += '\n\n'
            if reverse:
                revoutput.append(currout)
            else:
                output.write(currout)
        for currout in reversed(revoutput):
            output.write(currout)
        output.flush()

if __name__ == '__main__':
    groupoutput = GroupedData()
    for line in sys.stdin.read().split('\n'):
        if not line:
            continue
        groupoutput.add_line(*line.split(': ', 1))
    groupoutput.print_deviants()