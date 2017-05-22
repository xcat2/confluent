#!/usr/bin/env python


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
            currtrace = line
        elif currtrace is not None:
            currtrace += line + '\n'
for trace in sorted(threadtraces, key=lambda x: threadtraces[x]):
    print('Following stack seen {0} times'.format(threadtraces[trace]))
    print(trace)
