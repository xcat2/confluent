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
        return creds[email]

    def save_credential_for_user(self, email, credential):
        creds[email] = credential

    def save_challenge_for_user(self, email, challenge, type):
        challenges[email] = challenge

    def get_challenge_for_user(self, email, type):
        return challenges[email]


def handle_api_request(url, env, start_response, username, cfm, headers):
    if env['REQUEST_METHOD'] != 'POST':
        raise Exception('Only POST supported for webauthn operations')
    url = url.replace('/sessions/current/webauthn', '')
    if'CONTENT_LENGTH' in env and int(env['CONTENT_LENGTH']) > 0:
        reqbody = env['wsgi.input'].read(int(env['CONTENT_LENGTH']))
        reqtype = env['CONTENT_TYPE']
    if url == '/registration_options':
        rp = pywarp.RelyingPartyManager('Confluent Web UI', credential_storage_backend=TestBackend())
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
        start_response('200 OK', headers)
        yield json.dumps(opts)
