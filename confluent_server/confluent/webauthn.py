import base64
import confluent.util as util
import json
import pywarp
import pywarp.backends

creds = {}
challenges = {}

class TestBackend(pywarp.backends.CredentialStorageBackend):
    def __init__(self):
        pass

    def get_credential_by_email(self, email):
        if not isinstance(email, str):
            email = email.decode('utf8')
        return creds[email]

    def save_credential_for_user(self, email, credential):
        if not isinstance(email, str):
            email = email.decode('utf8')
        creds[email] = credential

    def save_challenge_for_user(self, email, challenge, type):
        challenges[email] = challenge

    def get_challenge_for_user(self, email, type):
        return challenges[email]


def handle_api_request(url, env, start_response, username, cfm, headers, reqbody):
    if env['REQUEST_METHOD'] != 'POST':
        raise Exception('Only POST supported for webauthn operations')
    url = url.replace('/sessions/current/webauthn', '')
    if url == '/registration_options':
        rp = pywarp.RelyingPartyManager('Confluent Web UI', credential_storage_backend=TestBackend(), require_attestation=False)
        userinfo = cfm.get_user(username)
        if not userinfo:
            cfm.create_user(username, role='Stub')
            userinfo = cfm.get_user(username)
        authid = userinfo.get('authid', None)
        if not authid:
            authid = util.randomstring(64)
            cfm.set_user(username, {'authid': authid})
        opts = rp.get_registration_options(username)
        # pywarp generates an id derived
        # from username, which is a 'must not' in the spec
        # we replace that with a complying approach
        opts['user']['id'] = authid
        if 'icon' in opts['user']:
            del opts['user']['icon']
        if 'id' in opts['rp']:
            del opts['rp']['id']
        start_response('200 OK', headers)
        yield json.dumps(opts)
    elif url.startswith('/registered_credentials/'):
        username = url.rsplit('/', 1)[-1]
        rp = pywarp.RelyingPartyManager('Confluent Web UI', credential_storage_backend=TestBackend())
        if not isinstance(username, bytes):
            username = username.encode('utf8')
        opts = rp.get_authentication_options(username)
        opts['challenge'] = base64.b64encode(opts['challenge']).decode('utf8')
        start_response('200 OK', headers)
        yield json.dumps(opts)
    elif url == '/validate':
        rp = pywarp.RelyingPartyManager('Confluent Web UI', credential_storage_backend=TestBackend())
        req = json.loads(reqbody)
        for x in req:
            req[x] = base64.b64decode(req[x].replace('-', '+').replace('_', '/'))
        req['email'] = username
        rsp = rp.verify(**req)
        start_response('200 OK')
        yield json.dumps(rsp)
    elif url == '/register_credential':
        rp = pywarp.RelyingPartyManager('Confluent Web UI', credential_storage_backend=TestBackend(), require_attestation=False)
        req = json.loads(reqbody)
        for x in req:
            req[x] = base64.b64decode(req[x].replace('-', '+').replace('_', '/'))
        if not isinstance(username, bytes):
            username = username.encode('utf8')
        req['email'] = username
        rsp = rp.register(**req)
        start_response('200 OK', headers)
        yield json.dumps(rsp)