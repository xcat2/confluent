import base64
import confluent.tlvdata as tlvdata
import confluent.util as util
import json
import pywarp
import pywarp.backends
import pywarp.credentials

challenges = {}

class ConfluentBackend(pywarp.backends.CredentialStorageBackend):
    def __init__(self, cfg):
        self.cfg = cfg

    def get_credential_ids_by_email(self, email):
        if not isinstance(email, str):
            email = email.decode('utf8')
        authenticators = self.cfg.get_user(email).get('authenticators', {})
        if not authenticators:
            raise Exception('No authenticators found')
        for cid in authenticators:
            yield base64.b64decode(cid)

    def get_credential_by_email_id(self, email, id):
        if not isinstance(email, str):
            email = email.decode('utf8')
        authenticators = self.cfg.get_user(email).get('authenticators', {})
        cid = base64.b64encode(id).decode('utf8')
        pk = authenticators[cid]['cpk']
        pk = base64.b64decode(pk)
        return pywarp.credentials.Credential(credential_id=id, credential_public_key=pk)

    def get_credential_by_email(self, email):
        if not isinstance(email, str):
            email = email.decode('utf8')
        authenticators = self.cfg.get_user(email)
        cid = list(authenticators)[0]
        cred = authenticators[cid]
        cid = base64.b64decode(cred['cid'])
        cpk = base64.b64decode(cred['cpk'])
        return pywarp.credentials.Credential(credential_id=cid, credential_public_key=cpk)

    def save_credential_for_user(self, email, credential):
        if not isinstance(email, str):
            email = email.decode('utf8')
        cid = base64.b64encode(credential.id).decode('utf8')
        credential = {'cid': cid, 'cpk': base64.b64encode(bytes(credential.public_key)).decode('utf8')}
        authenticators = self.cfg.get_user(email).get('authenticators', {})
        authenticators[cid] = credential
        self.cfg.set_user(email, {'authenticators': authenticators})

    def save_challenge_for_user(self, email, challenge, type):
        if not isinstance(email, str):
            email = email.decode('utf8')
        challenges[email] = challenge

    def get_challenge_for_user(self, email, type):
        if not isinstance(email, str):
            email = email.decode('utf8')
        return challenges[email]


def handle_api_request(url, env, start_response, username, cfm, headers, reqbody, authorized):
    if env['REQUEST_METHOD'] != 'POST':
        raise Exception('Only POST supported for webauthn operations')
    url = url.replace('/sessions/current/webauthn', '')
    if url == '/registration_options':
        rp = pywarp.RelyingPartyManager('Confluent Web UI', credential_storage_backend=ConfluentBackend(cfm), require_attestation=False)
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
        rp = pywarp.RelyingPartyManager('Confluent Web UI', credential_storage_backend=ConfluentBackend(cfm))
        if not isinstance(username, bytes):
            username = username.encode('utf8')
        opts = rp.get_authentication_options(username)
        opts['challenge'] = base64.b64encode(opts['challenge']).decode('utf8')
        start_response('200 OK', headers)
        yield json.dumps(opts)
    elif url.startswith('/validate/'):
        username = url.rsplit('/', 1)[-1]
        if not isinstance(username, bytes):
            username = username.encode('utf8')
        rp = pywarp.RelyingPartyManager('Confluent Web UI', credential_storage_backend=ConfluentBackend(cfm))
        req = json.loads(reqbody)
        for x in req:
            req[x] = base64.b64decode(req[x].replace('-', '+').replace('_', '/'))
        req['email'] = username
        rsp = rp.verify(**req)
        if start_response:
            start_response('200 OK', headers)
            sessinfo = {'username': username}
            if 'authtoken' in authorized:
                sessinfo['authtoken'] = authorized['authtoken']
            if 'sessionid' in authorized:
                sessinfo['sessionid'] = authorized['sessionid']
            tlvdata.unicode_dictvalues(sessinfo)
            yield json.dumps(sessinfo)
        else:
            yield rsp
    elif url == '/register_credential':
        rp = pywarp.RelyingPartyManager('Confluent Web UI', credential_storage_backend=ConfluentBackend(cfm), require_attestation=False)
        req = json.loads(reqbody)
        for x in req:
            req[x] = base64.b64decode(req[x].replace('-', '+').replace('_', '/'))
        if not isinstance(username, bytes):
            username = username.encode('utf8')
        req['email'] = username
        rsp = rp.register(**req)
        start_response('200 OK', headers)
        yield json.dumps(rsp)