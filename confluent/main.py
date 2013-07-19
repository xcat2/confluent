# Copyright 2013 IBM Corporation
# All rights reserved

# This is the main application.
# It should check for existing UDP socket to negotiate socket listen takeover
# It will have three paths into it:
#   -Unix domain socket
#   -TLS socket
#   -WSGI
# Additionally, it will be able to receive particular UDP packets to facilitate
# Things like heartbeating and discovery
# It also will optionally snoop SLP DA requests

import eventlet
from eventlet.green import socket
from eventlet import wsgi
import multiprocessing
import sys
import os

pluginmap = {}
def _load_plugins():
    # To know our plugins directory, we get the parent path of 'bin'
    path=os.path.dirname(os.path.realpath(__file__))
    plugindir = os.path.realpath(os.path.join(path,'..','plugins'))
    sys.path.append(plugindir)
    plugins = set()
    #two passes, to avoid adding both py and pyc files
    for plugin in os.listdir(plugindir):
        plugin = os.path.splitext(plugin)[0]
        plugins.add(plugin)
    for plugin in plugins:
        tmpmod = __import__(plugin)
        

def run():
    _load_plugins()
