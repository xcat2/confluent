# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 IBM Corporation
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

#construct custom grammar with pyparsing

#>>> grammar = pyparsing.Word(pyparsing.alphanums+'/', pyparsing.alphanums+'[]-.*') | ',-' | ',' | '@'
#>>> parser = pyparsing.nestedExpr('(',')',content=grammar)
#>>> parser.parseString("(n1-n4,compute,(foo@bar),-bob,bob)").asList()
#[['n1-n4', ',', 'compute', ',', ['foo', '@', 'bar'], ',-', 'bob', ',', 'bob']]
import pyparsing
import re

class NodeRange(object):
    """Iterate over a noderange

    :param noderange: string representing a noderange to evaluate
    :param verify: whether or not to perform lookups in the config
    """
    _grammar = \
        pyparsing.Word(
            pyparsing.alphanums + '=', pyparsing.alphanums + '[]-.*+') | \
        ',-' | ',' | '@'
    _parser = pyparsing.nestedExpr(content=_grammar)
    def __init__(self, noderange, verify=True):
        self.verify = verify
        elements = self._parser.parseString("(" + noderange + ")").asList()
        self._noderange = self._evaluate(elements)
        print self._noderange

    def _evaluate(self, parsetree):
        current_op = 0 # enum, 0 union, 1 subtract, 2 intersect
        current_range = set([])
        if not isinstance(parsetree,list):  # down to a plain text thing
            return self._expandstring(parsetree)
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
                current_range -= self._evaluate(elem)
            elif current_op == 2:
                current_range &= self._evaluate(elem)
        return current_range

    def _expandstring(self, element):
        if self.verify:
            #this is where we would check for exactly this
            raise Exception("TODO: link with actual config")
        #this is where we would check for a literal groupname
        #ok, now time to understand the various things
        if '[' in element:  #[] style expansion
            raise Exception("TODO: [] in expression")
        elif '-' in element:  # *POSSIBLE* range, could just be part of name
            raise Exception("TODO: ranged expression")
        elif ':' in element:  # : range for less ambiguity
            raise Exception("TODO: ranged expression")
        if not self.verify:
            return set([element])
