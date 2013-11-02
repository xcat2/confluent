# Copyright (C) IBM 2013
# All rights reserved
# This SCGI server provides a http wrap to confluent api
# It additionally manages httprequest console sessions as supported by
# shillinabox javascript
import base64
import Cookie
import confluent.auth as auth
import confluent.consoleserver as consoleserver
import confluent.exceptions as exc
import confluent.pluginapi as pluginapi
import confluent.util as util
import eventlet
import json
import os
import string
import time
import urlparse
import eventlet.wsgi
#scgi = eventlet.import_patched('flup.server.scgi')


consolesessions = {}
httpsessions = {}


def _sessioncleaner():
    while (1):
        currtime = time.time()
        for session in httpsessions.keys():
            if httpsessions[session]['expiry'] < currtime:
                del httpsessions[session]
        for session in consolesessions.keys():
            if consolesessions[session]['expiry'] < currtime:
                del consolesessions[session]
        eventlet.sleep(10)


def _get_query_dict(env, reqbody, reqtype):
    qdict = {}
    try:
        qstring = env['QUERY_STRING']
    except KeyError:
        qstring = None
    if qstring:
        for qpair in qstring.split('&'):
            qkey, qvalue = qpair.split('=')
            qdict[qkey] = qvalue
    if reqbody is not None:
        if "application/x-www-form-urlencoded" in reqtype:
            pbody = urlparse.parse_qs(reqbody)
            for ky in pbody.iterkeys():
                qdict[ky] = pbody[ky][0]
    return qdict


def _authorize_request(env):
    """Grant/Deny access based on data from wsgi env

    """
    authdata = False
    cookie = Cookie.SimpleCookie()
    if 'HTTP_COOKIE' in env:
        #attempt to use the cookie.  If it matches
        cc = Cookie.SimpleCookie()
        cc.load(env['HTTP_COOKIE'])
        if 'confluentsessionid' in cc:
            sessionid = cc['confluentsessionid'].value
            if sessionid in httpsessions:
                httpsessions[sessionid]['expiry'] = time.time() + 90
                name = httpsessions[sessionid]['name']
                authdata = auth.authorize(name, element=None)
    if authdata is False and 'HTTP_AUTHORIZATION' in env:
        name, passphrase = base64.b64decode(
                env['HTTP_AUTHORIZATION'].replace('Basic ','')).split(':',1)
        authdata = auth.check_user_passphrase(name, passphrase, element=None)
        sessid = util.randomstring(32)
        while sessid in httpsessions:
            sessid = util.randomstring(32)
        httpsessions[sessid] = {'name': name, 'expiry': time.time() + 90}
        cookie['confluentsessionid']=sessid
        cookie['confluentsessionid']['secure'] = 1
        cookie['confluentsessionid']['httponly'] = 1
        cookie['confluentsessionid']['path'] = '/'
    if authdata:
        return {'code': 200,
                'cookie': cookie,
                'cfgmgr': authdata[1],
                'userdata': authdata[0]}
    else:
        return {'code': 401}
    # TODO(jbjohnso): actually evaluate the request for authorization
    # In theory, the x509 or http auth stuff will get translated and then
    # passed on to the core authorization function in an appropriate form
    # expresses return in the form of http code
    # 401 if there is no known identity
    # 403 if valid identity, but no access
    # going to run 200 just to get going for now


def _pick_mimetype(env):
    """Detect the http indicated mime to send back.

    Note that as it gets into the ACCEPT header honoring, it only looks for
    application/json and else gives up and assumes html.  This is because
    browsers are very chaotic about ACCEPT HEADER.  It is assumed that
    XMLHttpRequest.setRequestHeader will be used by clever javascript
    if the '.json' scheme doesn't cut it.
    """
    if env['PATH_INFO'].endswith('.json'):
        return 'application/json'
    elif env['PATH_INFO'].endswith('.html'):
        return 'text/html'
    elif 'application/json' in env['HTTP_ACCEPT']:
        return 'application/json'
    else:
        return 'text/html'


def _assign_consessionid(consolesession):
    sessid = util.randomstring(32)
    while sessid in consolesessions.keys():
        sessid = util.randomstring(32)
    consolesessions[sessid] = {'session': consolesession,
        'expiry': time.time() + 60}
    return sessid

def resourcehandler(env, start_response):
    """Function to handle new wsgi requests
    """
    authorized = _authorize_request(env)
    mimetype = _pick_mimetype(env)
    reqbody = None
    reqtype = None
    if 'CONTENT_LENGTH' in env and int(env['CONTENT_LENGTH']) > 0:
        reqbody = env['wsgi.input'].read(int(env['CONTENT_LENGTH']))
        reqtype = env['CONTENT_TYPE']
    if authorized['code'] == 401:
        start_response('401 Authentication Required',
            [('Content-type', 'text/plain'),
            ('WWW-Authenticate', 'Basic realm="confluent"')])
        yield 'authentication required'
        return
    if authorized['code'] == 403:
        start_response('403 Forbidden',
            [('Content-type', 'text/plain'),
            ('WWW-Authenticate', 'Basic realm="confluent"')])
        yield 'authorization failed'
        return
    if authorized['code'] != 200:
        raise Exception("Unrecognized code from auth engine")
    headers = [('Content-Type', 'application/json; charset=utf-8')]
    headers.extend(("Set-Cookie", m.OutputString())
            for m in authorized['cookie'].values())
    cfgmgr = authorized['cfgmgr']
    querydict = _get_query_dict(env, reqbody, reqtype)
    if '/console/session' in env['PATH_INFO']:
        #hard bake JSON into this path, do not support other incarnations
        prefix, _, _ = env['PATH_INFO'].partition('/console/session')
        _, _, nodename = prefix.rpartition('/')
        if 'session' not in querydict.keys() or not querydict['session']:
            # Request for new session
            consession = consoleserver.ConsoleSession(node=nodename,
                                                configmanager=cfgmgr)
            if not consession:
                start_response("500 Internal Server Error", headers)
                return
            sessid = _assign_consessionid(consession)
            start_response('200 OK', headers)
            yield '{"session":"%s","data":""}' % sessid
            return
        elif 'keys' in querydict.keys():
            # client wishes to push some keys into the remote console
            input = ""
            for idx in xrange(0, len(querydict['keys']), 2):
                input += chr(int(querydict['keys'][idx:idx+2],16))
            sessid = querydict['session']
            consolesessions[sessid]['expiry'] = time.time() + 90
            consolesessions[sessid]['session'].write(input)
            start_response('200 OK', headers)
            return # client has requests to send or receive, not both...
        else: #no keys, but a session, means it's hooking to receive data
            sessid = querydict['session']
            consolesessions[sessid]['expiry'] = time.time() + 90
            outdata = consolesessions[sessid]['session'].get_next_output(timeout=45)
            try:
                rsp = json.dumps({'session': querydict['session'], 'data': outdata})
            except UnicodeDecodeError:
                rsp = json.dumps({'session': querydict['session'], 'data': outdata}, encoding='cp437')
            except UnicodeDecodeError:
                rsp = json.dumps({'session': querydict['session'], 'data': 'DECODEERROR'})
            start_response('200 OK', headers)
            yield rsp
            return
    else:
        try:
            hdlr = pluginapi.handle_path(env['PATH_INFO'], 'retrieve', cfgmgr)
        except exc.NotFoundException:
            start_response('404 Not found', headers)
            yield "404 - Request path not recognized"
            return
        start_response('200 OK', headers)
        yield '['
        docomma = False
        for rsp in hdlr:
            if docomma:
                yield ','
            else:
                docomma = True
            yield rsp.json()
        yield ']'


def serve():
    # TODO(jbjohnso): move to unix socket and explore
    # either making apache deal with it
    # or just supporting nginx or lighthttpd
    # for now, http port access
    #scgi.WSGIServer(resourcehandler, bindAddress=("localhost",4004)).run()
    #based on a bakeoff perf wise, eventlet http support proxied actually did
    #edge out patched flup.  unpatched flup was about the same as eventlet http
    #but deps are simpler without flup
    #also, the potential for direct http can be handy
    #todo remains unix domain socket for even http
    eventlet.wsgi.server(eventlet.listen(("",4005)),resourcehandler)


class HttpApi(object):
    def start(self):
        self.server = eventlet.spawn(serve)

_cleaner = eventlet.spawn(_sessioncleaner)




