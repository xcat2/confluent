#!/usr/bin/python2
import pyghmi.util.webclient as webclient
import json
import os
import sys

missingargs = False
if 'XCCUSER' not in os.environ:
    print('Must set XCCUSER environment variable')
    missingargs = True
if 'XCCPASS' not in os.environ:
    print('Must set XCCPASS environment variable')
    missingargs = True
if missingargs:
    sys.exit(1)

w = webclient.SecureHTTPConnection(sys.argv[1], 443, verifycallback=lambda x: True)
w.connect()
adata = json.dumps({'username': os.environ['XCCUSER'], 'password': os.environ['XCCPASS']})
headers = {'Connection': 'keep-alive', 'Content-Type': 'application/json'}
w.request('POST', '/api/login', adata, headers)
rsp = w.getresponse()
if rsp.status == 200:
     rspdata = json.loads(rsp.read())
     w.set_header('Content-Type', 'application/json')
     w.set_header('Authorization', 'Bearer ' + rspdata['access_token'])
     if '_csrf_token' in w.cookies:
         w.set_header('X-XSRF-TOKEN', w.cookies['_csrf_token'])
     print(repr(w.grab_json_response('/api/dataset', {
         'USER_GlobalPassComplexRequired': '0',
     })))
     
