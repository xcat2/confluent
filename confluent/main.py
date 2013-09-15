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

import confluent.pluginapi as pluginapi
import confluent.httpapi as httpapi
import confluent.sockapi as sockapi
import eventlet
from eventlet.green import socket
from eventlet import wsgi
import multiprocessing
import sys
import os

def run():
    pluginapi.load_plugins()
    webservice = httpapi.HttpApi()
    webservice.start()
    sockservice = sockapi.SockApi()
    sockservice.start()
    while (1):
        eventlet.sleep(100)

