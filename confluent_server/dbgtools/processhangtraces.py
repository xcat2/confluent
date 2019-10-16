#!/usr/bin/python2

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

import sys

threadtraces = {}

with open(sys.argv[1]) as tracefile:
    traces = tracefile.read()
    currtrace = None
    for line in traces.split("\n"):
        if line.startswith("Thread trace:"):
            if currtrace is not None:
                if currtrace not in threadtraces:
                    threadtraces[currtrace] = 0
                threadtraces[currtrace] += 1
            currtrace = ''
        elif currtrace is not None:
            currtrace += line + '\n'
for trace in sorted(threadtraces, key=lambda x: threadtraces[x]):
    print('Following stack seen {0} times'.format(threadtraces[trace]))
    print(trace)
