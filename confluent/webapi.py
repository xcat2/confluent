# Copyright (C) IBM 2013
# All rights reserved
# This SCGI server provides a http wrap to confluent api
# It additionally manages httprequest console sessions as supported by
# shillinabox javascript
import base64
import confluent.console as console
import confluent.util as util
import eventlet
import os
import string
scgi = eventlet.import_patched('flup.server.scgi')


consolesessions = {}


def _get_query_dict(qstring):
    qdict = {}
    if not qstring:
        return qdict
    for qpair in qstring.split('&'):
        qkey, qvalue = qpair.split('=')
        qdict[qkey] = qvalue
    return qdict


def _authorize_request(env):
    """Grant/Deny access based on data from wsgi env

    """
    # TODO(jbjohnso): actually evaluate the request for authorization
    # In theory, the x509 or http auth stuff will get translated and then
    # passed on to the core authorization function in an appropriate form
    # expresses return in the form of http code
    # 401 if there is no known identity
    # 403 if valid identity, but no access
    # going to run 200 just to get going for now
    return 200


def _format_response(response):


def _pick_mimetype(env):
    """Detect the http indicated mime to send back.

    Note that as it gets into the ACCEPT header honoring, it only looks for
    application/json and else gives up and assumes html.  This is because
    browsers are too terrible.  It is assumed that
    XMLHttpRequest.setRequestHeader will be used by clever javascript
    if the '.json' scheme doesn't cut it.
    """
    # TODO(jbjohnso): will this scheme actually play nice with shellinabox?
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
    print repr(env)
    if authorized in (401, 403):
        start_response(authorized, [])
        return
    querydict = _get_query_dict(env['QUERY_STRING'])
    if '/console/session' in env['PATH_INFO']:
        prefix, _, _ = env['PATH_INFO'].partition('/console/session')
        _, _, nodename = prefix.rpartition('/')
        if 'session' not in querydict.keys() or not querydict['session']:
            # Request for new session
            consession = console.ConsoleSession(node=nodename)
            if not consession:
                start_response("500 Internal Server Error", [])
                return
            sessid = _assign_consessionid(consession)
            start_response('200 OK', [('Content-Type', 'application/json; charset=utf-8')])
            return [d+'","data":""}']
    start_response('404 Not Found', [])
    return []

class HttpApi(object):
    def start(self):
        # TODO(jbjohnso): move to unix socket and explore
        # either making apache deal with it
        # or just supporting nginx or lighthttpd
        # for now, http port access
        self.server = eventlet.spawn(
            scgi.WSGIServer(resourcehandler,
                            bindAddress=("localhost",4004)).run())




