#!/usr/bin/python3
import pyghmi.util.webclient as webclient
from xml.etree.ElementTree import fromstring
import os
import sys

tmppassword = 'to3BdS91ABrd'
missingargs = False
if 'SMMUSER' not in os.environ:
    print('Must set SMMUSER environment variable')
    missingargs = True
if 'SMMPASS' not in os.environ:
    print('Must set SMMPASS environment variable')
    missingargs = True
if missingargs:
    sys.exit(1)

w = webclient.SecureHTTPConnection(sys.argv[1], 443, verifycallback=lambda x: True)
w.connect()
adata = 'user={0}&password={1}'.format(os.environ['SMMUSER'], os.environ['SMMPASS'])
bdata = 'user={0}&password={1}'.format(os.environ['SMMUSER'], tmppassword)
headers = {'Connection': 'keep-alive', 'Content-Type': 'application/x-www-form-urlencoded'}
w.request('POST', '/data/login', adata, headers)
rsp = w.getresponse()
rspdata = rsp.read().decode('utf8')
restorepwd = False
if 'authResult>1' in rspdata:
     restorepwd = True
     w.request('POST', '/data/login', bdata, headers)
     rsp = w.getresponse()
     rspdata = rsp.read()
if 'renew_account' in rspdata:
     restorepwd = True
     tokens = fromstring(rspdata)
     st2 = tokens.findall('st2')[0].text
     w.set_header('ST2', st2)
     w.request('POST', '/data/changepwd', 'oripwd={0}&newpwd={1}'.format(os.environ['SMMPASS'], tmppassword))
     rsp = w.getresponse()
     rspdata = rsp.read()
     w.request('POST', '/data/login', bdata, headers)
     rsp = w.getresponse()
     rspdata = rsp.read()
if 'authResult>0' in rspdata:
     tokens = fromstring(rspdata)
     st2 = tokens.findall('st2')[0].text
     w.set_header('ST2', st2)
     rules = 'set=passwordDurationDays:0,passwordExpireWarningDays:0,passwordChangeInterval:0,passwordChangeInterval:0'
     w.request('POST', '/data', rules)
     rsp = w.getresponse()
     print(repr(rsp.read()))
     if restorepwd:
         w.request('POST', '/data/changepwd', 'oripwd={1}&newpwd={0}'.format(os.environ['SMMPASS'], tmppassword))
         rsp = w.getresponse()
         print(repr(rsp.read()))
