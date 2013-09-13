# Copyright (C) IBM 2013
# All rights reserved
# This SCGI server provides a http wrap to confluent api
# It additionally manages httprequest console sessions as supported by
# shillinabox javascript
import base64
import confluent.console as console
import confluent.auth as auth
import confluent.util as util
import eventlet
import os
import string
import urlparse
scgi = eventlet.import_patched('flup.server.scgi')


consolesessions = {}


def _get_query_dict(qstring, reqbody, reqtype):
    qdict = {}
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
    if 'REMOTE_USER' in env:  # HTTP Basic auth passed
        user = env['REMOTE_USER']
        #TODO: actually pass in the element
        authdata = auth.authorize(user, element=None)
        if authdata is None:
            return {'code': 401}
        else:
            return {'code': 200,
                    'cfgmgr': authdata[1],
                    'userdata': authdata[0]}

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
    sessid = util.randomstring(20)
    while sessid in consolesessions.keys():
        sessid = util.randomstring(20)
    consolesessions[sessid] = consolesession
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
    print env
    if authorized['code'] == 401:
        start_response('401 Authentication Required',
            [('Content-type', 'text/plain'),
             ('WWW-Authenticate', 'Basic realm="confluent"')])
        return 'authentication required'
    if authorized['code'] == 403:
        start_response('403 Forbidden',
            [('Content-type', 'text/plain'),
             ('WWW-Authenticate', 'Basic realm="confluent"')])
        return 'authorization failed'
    if authorized['code'] != 200:
        raise Exception("Unrecognized code from auth engine")
    cfgmgr = authorized['cfgmgr']
    querydict = _get_query_dict(env['QUERY_STRING'], reqbody, reqtype)
    if '/console/session' in env['PATH_INFO']:
        #hard bake JSON into this path, do not support other incarnations
        prefix, _, _ = env['PATH_INFO'].partition('/console/session')
        _, _, nodename = prefix.rpartition('/')
        if 'session' not in querydict.keys() or not querydict['session']:
            # Request for new session
            consession = console.ConsoleSession(node=nodename,
                                                configmanager=cfgmgr)
            if not consession:
                start_response("500 Internal Server Error", [])
                return
            sessid = _assign_consessionid(consession)
            start_response('200 OK', [('Content-Type',
                'application/json; charset=utf-8')])
            return ['{"session":"%s","data":""}' % sessid]
        elif 'keys' in querydict.keys():
            # client wishes to push some keys into the remote console
            input = ""
            for idx in xrange(0, len(querydict['keys'])):
                input += chr(int(querydict['keys'][idx:idx+2]))
            print "taking in "+input
            sessid = querydict['session']
            consolesessions[sessid].write(input)
            start_response('200 OK', [('Content-Type',
                'application/json; charset=utf-8')])
            return # client has requests to send or receive, not both...
        else: #no keys, but a session, means it's hooking to receive data
            sessid = querydict['session']
            outdata = consolesessions[sessid].get_next_output(timeout=45)
            json = '{"session":"%s","data":"%s"}'%(querydict['session'],
                                                    outdata)
    start_response('404 Not Found', [])
    return ["Unrecognized directive (404)"]

class HttpApi(object):
    def start(self):
        # TODO(jbjohnso): move to unix socket and explore
        # either making apache deal with it
        # or just supporting nginx or lighthttpd
        # for now, http port access
        self.server = eventlet.spawn(
            scgi.WSGIServer(resourcehandler,
                            bindAddress=("localhost",4004)).run())




