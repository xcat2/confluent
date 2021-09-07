#!/usr/bin/python2
import pyghmi.util.webclient as webclient
import json
import os
import sys

missingargs = False
if 'XCCPASS' not in os.environ:
    print('Must set XCCPASS environment variable')
    missingargs = True
if missingargs:
    sys.exit(1)

w = webclient.SecureHTTPConnection(sys.argv[1], 443, verifycallback=lambda x: True)
w.connect()
adata = json.dumps({'username': 'USERID', 'password': 'PASSW0RD'})
headers = {'Connection': 'keep-alive', 'Content-Type': 'application/json'}
w.request('POST', '/api/login', adata, headers)
rsp = w.getresponse()
if rsp.status == 200:
     rspdata = json.loads(rsp.read())
     w.set_header('Content-Type', 'application/json')
     w.set_header('Authorization', 'Bearer ' + rspdata['access_token'])
     if '_csrf_token' in w.cookies:
         w.set_header('X-XSRF-TOKEN', w.cookies['_csrf_token'])
     if rspdata.get('pwchg_required', False):
         print(repr(w.grab_json_response('/api/function', {'USER_UserPassChange': os.environ['XCCPASS']})))
     print(repr(w.grab_json_response('/api/dataset', {
         'USER_GlobalPassExpWarningPeriod': '0', 
         'USER_GlobalPassExpPeriod': '0', 
         'USER_GlobalMinPassReuseCycle': '0', 
         'USER_GlobalMinPassReuseCycle': '0', 
         'USER_GlobalMinPassChgInt': '0', 
     })))
     #print(repr(w.grab_json_response('/api/function', {'USER_UserPassChange': '1,' + os.environ['XCCPASS']})))
     
