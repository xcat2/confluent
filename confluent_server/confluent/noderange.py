# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 IBM Corporation
# Copyright 2015-2017 Lenovo
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
# this will implement noderange grammar

# considered ast, but a number of things violate python grammar like [] in
# the middle of strings and use of @ for anything is not in their syntax


import copy
import itertools
import pyparsing as pp
import re

try:
    range = xrange
except NameError:
    pass

# construct custom grammar with pyparsing
_nodeword = pp.Word(pp.alphanums + '~^$/=-_:.*+!')
_nodebracket = pp.QuotedString(quoteChar='[', endQuoteChar=']',
                               unquoteResults=False)
_nodeatom = pp.Group(pp.OneOrMore(_nodeword | _nodebracket))
_paginationstart = pp.Group(pp.Word('<', pp.nums))
_paginationend = pp.Group(pp.Word('>', pp.nums))
_grammar = _nodeatom | ',-' | ',' | '@' | _paginationstart | _paginationend
_parser = pp.nestedExpr(content=_grammar)

_numextractor = pp.OneOrMore(pp.Word(pp.alphas + '-') | pp.Word(pp.nums))

numregex = re.compile('([0-9]+)')

lastnoderange = None

def humanify_nodename(nodename):
    """Analyzes nodename in a human way to enable natural sort

    :param nodename: The node name to analyze
    :returns: A structure that can be consumed by 'sorted'
    """
    return [int(text) if text.isdigit() else text.lower()
            for text in re.split(numregex, nodename)]

def unnumber_nodename(nodename):
    # stub out numbers
    chunked = ["{}" if text.isdigit() else text.lower()
            for text in re.split(numregex, nodename)]
    return chunked

def getnumbers_nodename(nodename):
    return [int(x) for x in re.split(numregex, nodename) if x.isdigit()]
    
def group_elements(elems):
    """ Take the specefied elements and chunk them according to text similarity
    """
    prev = None
    currchunk = []
    chunked_elems = [currchunk]
    for elem in elems:
        elemtxt = unnumber_nodename(elem)
        if not prev:
            prev = elemtxt
            currchunk.append(elem)
            continue
        if prev == elemtxt:
            currchunk.append(elem)
        else:
            currchunk = [elem]
            chunked_elems.append(currchunk)
            prev = elemtxt
    return chunked_elems

def abbreviate_chunk(chunk, validset):
    if len(chunk) < 3:
        return sorted(chunk, key=humanify_nodename)
    #chunk = sorted(chunk, key=humanify_nodename)
    vset = set(validset)
    cset = set(chunk)
    mins = None
    maxs = None
    for name in chunk:
        currns = getnumbers_nodename(name)
        if mins is None:
            mins = list(currns)
            maxs = list(currns)
            continue
        for n in range(len(currns)):
            if currns[n] < mins[n]:
                mins[n] = currns[n]
            if currns[n] > maxs[n]:
                maxs[n] = currns[n]
    tmplt = ''.join(unnumber_nodename(chunk[0]))
    bgnr = tmplt.format(*mins)
    endr = tmplt.format(*maxs)
    nr = '{}:{}'.format(bgnr, endr)
    prospect = NodeRange(nr).nodes
    ranges = []
    discontinuities = (prospect - vset).union(prospect - cset)
    currstart = None
    prevnode = None
    chunksize = 0
    prospect = sorted(prospect, key=humanify_nodename)
    currstart = prospect[0]
    while prospect:
        currnode = prospect.pop(0)
        if currnode in discontinuities:
            if chunksize == 0:
                continue
            elif chunksize == 1:
                ranges.append(prevnode)
            elif chunksize == 2:
                ranges.append(','.join([currstart, prevnode]))
            else:
                ranges.append(':'.join([currstart, prevnode]))
            chunksize = 0
            currstart = None
            continue
        elif not currstart:
            currstart = currnode
        chunksize += 1
        prevnode = currnode
    if chunksize == 1:
        ranges.append(prevnode)
    elif chunksize == 2:
        ranges.append(','.join([currstart, prevnode]))
    elif chunksize != 0:
        ranges.append(':'.join([currstart, prevnode]))
    return ranges


class ReverseNodeRange(object):
    """Abbreviate a set of nodes to a shorter noderange representation

    :param nodes: List of nodes as a list, tuple, etc.
    :param config: Config manager
    """

    def __init__(self, nodes, config):
        self.cfm = config
        self.nodes = set(nodes)


    @property
    def noderange(self):
        subsetgroups = []
        allgroups = self.cfm.get_groups(sizesort=True)
        for group in allgroups:
            if lastnoderange:
                for nr in lastnoderange:
                    if lastnoderange[nr] - self.nodes:
                        continue
                    if self.nodes - lastnoderange[nr]:
                        continue
                    return nr
            nl = set(
                self.cfm.get_nodegroup_attributes(group).get('nodes', []))
            if len(nl) > len(self.nodes) or not nl:
                continue
            if not nl - self.nodes:
                subsetgroups.append(group)
                self.nodes -= nl
                if not self.nodes:
                    break
        # then, analyze sequentially identifying matching alpha subsections
        # then try out noderange from beginning to end
        # we need to know discontinuities, which are either:
        # nodes that appear in the noderange that are not in the nodes
        # nodes that do not exist at all (we need a noderange modification 
        # that returns non existing nodes)
        ranges = []
        try:
            subsetgroups.sort(key=humanify_nodename)
            groupchunks = group_elements(subsetgroups)
            for gc in groupchunks:
                ranges.extend(abbreviate_chunk(gc, allgroups))
        except Exception:
            subsetgroups.sort()
        try:
            nodes = sorted(self.nodes, key=humanify_nodename)
            nodechunks = group_elements(nodes)
            for nc in nodechunks:
                ranges.extend(abbreviate_chunk(nc, self.cfm.list_nodes()))
        except Exception:
            ranges = sorted(self.nodes)
        return ','.join(ranges)



# TODO: pagination operators <pp.nums and >pp.nums for begin and end respective
class NodeRange(object):
    """Iterate over a noderange

    :param noderange: string representing a noderange to evaluate
    :param config: Config manager object to use to vet elements
    """

    def __init__(self, noderange, config=None, purenumeric=False):
        global lastnoderange
        self.beginpage = None
        self.endpage = None
        self.cfm = config
        self.purenumeric = purenumeric
        try:
            elements = _parser.parseString("(" + noderange + ")", parseAll=True).asList()[0]
        except pp.ParseException as pe:
            raise Exception("Invalid syntax")
        if noderange[0] in ('<', '>'):
            # pagination across all nodes
            self._evaluate(elements)
            self._noderange = set(self.cfm.list_nodes())
        else:
            self._noderange = self._evaluate(elements)
        lastnoderange = {noderange: set(self._noderange)}

    @property
    def nodes(self):
        if self.beginpage is None and self.endpage is None:
            return self._noderange
        sortedlist = list(self._noderange)
        try:
            sortedlist.sort(key=humanify_nodename)
        except TypeError:
            # The natural sort attempt failed, fallback to ascii sort
            sortedlist.sort()
        if self.beginpage is not None:
            sortedlist = sortedlist[self.beginpage:]
        if self.endpage is not None:
            sortedlist = sortedlist[:self.endpage]
        return set(sortedlist)

    def _evaluate(self, parsetree, filternodes=None):
        current_op = 0  # enum, 0 union, 1 subtract, 2 intersect
        current_range = set([])
        if not isinstance(parsetree[0], list):  # down to a plain text thing
            return self._expandstring(parsetree, filternodes)
        for elem in parsetree:
            if elem == ',-':
                current_op = 1
            elif elem == ',':
                current_op = 0
            elif elem == '@':
                current_op = 2
            elif current_op == 0:
                current_range |= self._evaluate(elem)
            elif current_op == 1:
                current_range -= self._evaluate(elem, current_range)
            elif current_op == 2:
                current_range &= self._evaluate(elem, current_range)
        return current_range

    def failorreturn(self, atom):
        if self.cfm is not None:
            raise Exception(atom + " not valid")
        return set([atom])

    def expandrange(self, seqrange, delimiter):
        increment = 1
        if self.purenumeric:
            seqranges = seqrange.replace('-', ':').replace('..', ':')
            pieces = seqranges.split(':')
            if len(pieces) > 3:
                raise Exception("Invalid numeric sequence")
            leftbits = [pieces[0]]
            rightbits = [pieces[1]]
            if len(pieces) == 3:
                increment = int(pieces[2])
        else:
            pieces = seqrange.split(delimiter)
            if len(pieces) % 2 != 0:
                return self.failorreturn(seqrange)
            halflen = len(pieces) // 2
            left = delimiter.join(pieces[:halflen])
            right = delimiter.join(pieces[halflen:])
            leftbits = _numextractor.parseString(left).asList()
            rightbits = _numextractor.parseString(right).asList()
            if len(leftbits) != len(rightbits):
                return self.failorreturn(seqrange)
        finalfmt = ''
        iterators = []
        for idx in range(len(leftbits)):
            if leftbits[idx] == rightbits[idx]:
                finalfmt += leftbits[idx]
            elif leftbits[idx][0] in pp.alphas or rightbits[idx][0] in pp.alphas:
                # if string portion unequal, not going to work
                return self.failorreturn(seqrange)
            else:
                curseq = []
                finalfmt += '{%d}' % len(iterators)
                iterators.append(curseq)
                leftnum = int(leftbits[idx])
                rightnum = int(rightbits[idx])
                if leftnum > rightnum:
                    return self.failorreturn(seqrange)
                    width = len(rightbits[idx])
                    minnum = rightnum
                    maxnum = leftnum + 1  # range goes to n-1...
                elif rightnum > leftnum:
                    width = len(leftbits[idx])
                    minnum = leftnum
                    maxnum = rightnum + 1
                else:  # differently padded, but same number...
                    return self.failorreturn(seqrange)
                numformat = '{0:0%d}' % width
                for num in range(minnum, maxnum, increment):
                    curseq.append(numformat.format(num))
        results = set([])
        for combo in itertools.product(*iterators):
            entname = finalfmt.format(*combo)
            results |= self.expand_entity(entname)
        return results

    def expand_entity(self, entname):
        if self.cfm is None or self.cfm.is_node(entname):
            return set([entname])
        if self.cfm.is_nodegroup(entname):
            grpcfg = self.cfm.get_nodegroup_attributes(entname)
            nodes = copy.copy(grpcfg['nodes'])
            if 'noderange' in grpcfg and grpcfg['noderange']:
                nodes |= NodeRange(
                    grpcfg['noderange']['value'], self.cfm).nodes
            return nodes
        raise Exception('Unknown node ' + entname)
        
    def _expandstring(self, element, filternodes=None):
        prefix = ''
        if element[0][0] in ('/', '~'):
            element = ''.join(element)
            nameexpression = element[1:]
            if self.cfm is None:
                raise Exception('Verification configmanager required')
            return set(self.cfm.filter_nodenames(nameexpression, filternodes))
        elif '=' in element[0] or '!~' in element[0]:
            element = ''.join(element)
            if self.cfm is None:
                raise Exception('Verification configmanager required')
            return set(self.cfm.filter_node_attributes(element, filternodes))
        for idx in range(len(element)):
            if element[idx][0] == '[':
                nodes = set([])
                for numeric in NodeRange(element[idx][1:-1], purenumeric=True).nodes:
                    nodes |= self._expandstring(
                        [prefix + numeric] + element[idx + 1:])
                return nodes
            else:
                prefix += element[idx]
        element = prefix
        if self.cfm is not None:
            # this is where we would check for exactly this
            if self.cfm.is_node(element):
                return set([element])
            if self.cfm.is_nodegroup(element):
                grpcfg = self.cfm.get_nodegroup_attributes(element)
                nodes = copy.copy(grpcfg['nodes'])
                if 'noderange' in grpcfg and grpcfg['noderange']:
                    nodes |= NodeRange(
                        grpcfg['noderange']['value'], self.cfm).nodes
                return nodes
        if ':' in element:  # : range for less ambiguity
            return self.expandrange(element, ':')
        elif '..' in element:
            return self.expandrange(element, '..')
        elif '-' in element:
            return self.expandrange(element, '-')
        elif '+' in element:
            element, increment = element.split('+')
            try:
                nodename, domain = element.split('.')
            except ValueError:
                nodename = element
                domain = ''
            increment = int(increment)
            elembits = _numextractor.parseString(nodename).asList()
            endnum = str(int(elembits[-1]) + increment)
            left = ''.join(elembits)
            if domain:
                left += '.' + domain
            right = ''.join(elembits[:-1])
            right += endnum
            if domain:
                right += '.' + domain
            nrange = left + ':' + right
            return self.expandrange(nrange, ':')
        elif '<' in element:
            self.beginpage = int(element[1:])
            return set([])
        elif '>' in element:
            self.endpage = int(element[1:])
            return set([])
        if self.cfm is None:
            return set([element])
        raise Exception(element + ' not a recognized node, group, or alias')
