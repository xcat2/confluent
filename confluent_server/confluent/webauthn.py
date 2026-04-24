import confluent.tlvdata as tlvdata
import confluent.util as util
import json
import copy
import base64
import secrets, time
from typing import Any, Optional
from webauthn import (
    generate_registration_options, 
    options_to_json, 
    generate_authentication_options,
    )
from webauthn import verify_registration_response
from webauthn import verify_authentication_response


challenges = {}

CONFIG_MANAGER = None

class Credential():
    def __init__(self, id, public_key):
        self.id = id
        self.credential_public_key = public_key 

def _load_credentials(creds):
    if creds is None:
        return None
    ret = copy.deepcopy(creds)
    ret['credential_public_key'] = base64.b64decode(creds['credential_public_key'])
    ret['id'] = base64.b64decode(creds['id'])
    return ret

def _load_authenticators(authenticators):
    ret = authenticators
    if 'challenges' in ret:
        if not ret['challenges'] is None:       
            ret['challenges']['request'] = base64.b64decode(ret['challenges']['request'])
    if 'credentials' in ret:
        ret['credentials'] = _load_credentials(ret['credentials'])
    return ret

class User():
    def __init__(self, id, username, user_handle, credential: Credential = None):
        self.id = id
        self.username = username
        self.user_handle = user_handle
        self.credentials = credential 

    def __parse_credentials(self): 
        if self.credentials:
            credid = base64.b64encode(self.credentials.id).decode()
            pubkey = base64.b64encode(self.credentials.credential_public_key).decode()
            return {"id": credid, "credential_public_key": pubkey}

    @staticmethod
    def seek_credential_by_id(credential_id):
        """
        There certainly is a better way to do this but for now lets try the wrong way that works 
        """
        credential_id = b64decode(credential_id)
        for username in CONFIG_MANAGER.list_users():
            authenticators = CONFIG_MANAGER.get_user(username).get('authenticators', {})
            authenticators = _load_authenticators(authenticators)
            try:
                credential = authenticators['credentials']
            except KeyError:
                continue
            if "id" in credential.keys() and credential["id"] == credential_id:
                return (Credential(id=credential["id"], public_key=credential["credential_public_key"]), username)
        return None
        
    
    @staticmethod
    def get_credential(credential_id, username):
        if not isinstance(username, str):
            username = username.decode('utf8')
        authenticators = CONFIG_MANAGER.get_user(username).get('authenticators', {})
        authenticators = _load_authenticators(authenticators)
        credential = authenticators.get('credentials', None)
        if credential is None:
            return None  
        if credential_id is None:
                return Credential(id=credential["id"], public_key=credential["credential_public_key"])
        return None


    @staticmethod
    def get(username):
        credentials_return = None
        if not CONFIG_MANAGER:
            raise Exception('config manager is not set up')
        if not isinstance(username, str):
            username = username.decode('utf8')
        userinfo = CONFIG_MANAGER.get_user(username)
        try:
            authenticators = CONFIG_MANAGER.get_user(username).get('authenticators', {})
        except AttributeError:
            return None
        if userinfo is None:
            return None
        authenticators = _load_authenticators(authenticators)
        b64authid = userinfo.get('webauthid', None)
        if b64authid is None:
            authid = None
        else:
            authid = base64.b64decode(b64authid)
        credential = authenticators.get("credentials", None)
        if credential:
            credentials_return = (Credential(credential['id'], credential["credential_public_key"]))
       
        return User(id=None, username=username, user_handle=authid, credential=credentials_return)

    async def save(self):
        authenticators = CONFIG_MANAGER.get_user(self.username).get('authenticators', {})
        authenticators = _load_authenticators(authenticators)
        authenticators['credentials'] = self.__parse_credentials()
        await CONFIG_MANAGER.set_user(self.username, {'authenticators': authenticators})


    def add(self, item):
        if isinstance(item, Credential):
            self.credentials = item
        else:
            raise Exception("Unsupported item type")
    
    def update(self, item):
        if isinstance(item, Credential):
            self.credentials = item
        else:
            raise Exception("Unsupported item type")


def registration_request(username, cfg, APP_RELYING_PARTY):
    user_model = User.get(username)
    if user_model is None:
        raise Exception("User not foud")

    options = generate_registration_options(
        rp_name=APP_RELYING_PARTY.name,
        rp_id=APP_RELYING_PARTY.id,
        user_id=user_model.user_handle,
        user_name=username)

    challenges[options.challenge] = username
    options_json = options_to_json(options)
    return options_json


def b64decode(data: str) -> bytes:
    """Decode base64, padding being optional.

    :param data: Base64 data as an ASCII byte string
    :returns: The decoded byte string.
    """
    data += '=' * (-len(data) % 4)  # Pad with '='s
    return base64.urlsafe_b64decode(data)

def get_challenge_from_response(rsp):
    cdj = rsp['response']['clientDataJSON']
    cdata = json.loads(b64decode(cdj))
    challenge = b64decode(cdata['challenge'])
    return challenge

async def registration_response(request, username, APP_RELYING_PARTY, APP_ORIGIN):
    challenge = get_challenge_from_response(request)
    if challenge not in challenges:
        raise Exception("Could not find challenge")
    chausername = challenges.pop(challenge, None)
    if chausername != username:
        raise Exception("Challenge does not match username")
    user_model = User.get(username)
    if not user_model:
        raise Exception("Invalid Username")
    try:
        registration_verification = verify_registration_response(
        credential=request,
        expected_challenge=challenge,
        expected_rp_id=APP_RELYING_PARTY.id,
        expected_origin=APP_ORIGIN,
        )
    except Exception as err:
        raise Exception("Could not handle credential attestation")
    
    credential = Credential(id=registration_verification.credential_id, public_key=registration_verification.credential_public_key)
    user_model.add(credential)
    await user_model.save()
    return {"verified": True}


def authentication_request(username, APP_RELYING_PARTY):
    if username:  # WebUI has supplied username and hit enter, only suggest webauthn if we have webauthn registered
        user_model = User.get(username)
        if not user_model:
            raise Exception("Invalid Username")
        credential_model = User.get_credential(credential_id=None, username=username)
        if not credential_model:
            raise Exception("No credential for user")
    options = generate_authentication_options(rp_id=APP_RELYING_PARTY.id)
    challenges[options.challenge] = username
    opts = options_to_json(options)
    return opts

def authentication_response(request, username, APP_RELYING_PARTY, APP_ORIGIN):
    if not username:
        credential_model, username = User.seek_credential_by_id(request['id'])
    else:
        credential_model = User.get_credential(credential_id=None, username=username)
    user_model = User.get(username)
    if not user_model:
        raise Exception("Invalid Username")
    challenge = get_challenge_from_response(request)
    expected_username = challenges.pop(challenge, None)
    if expected_username is None:
        raise Exception("No matching challenge")
    if not credential_model:
        raise Exception("No credential for user")
    
    verification = verify_authentication_response(
        credential=request,
        expected_challenge=challenge,
        expected_rp_id=APP_RELYING_PARTY.id,
        expected_origin=APP_ORIGIN,
        credential_public_key = credential_model.credential_public_key,
        credential_current_sign_count = 0,
    )
    return {"verified": True, "username": username}
    
class RpEntity(object):
    def __init__(self, name, id):
        self.name = name
        self.id = id 

async def handle_api_request(url, req, username, cfm, reqbody, authorized):
    """
        For now webauth is going to be limited to just one passkey per user 
        If you try to register a new passkey this will just clear the old one and register the new passkey
    """
    global CONFIG_MANAGER
    CONFIG_MANAGER = cfm

    APP_ORIGIN = 'https://' + req.headers['X-Forwarded-Host']
    HOST = req.headers['X-Forwarded-Host']
    APP_RELYING_PARTY = RpEntity(name='Confluent Web UI', id=HOST)
    if req.method != 'POST':
        raise Exception('Only POST supported for webauthn operations')
    url = url.replace('/sessions/current/webauthn', '')
    if url == '/registration_options':
        userinfo = cfm.get_user(username)
        if not userinfo:
            cfm.create_user(username, role='Stub')
            userinfo = cfm.get_user(username)
        authid = userinfo.get('webauthid', None)
        if not authid:  # TODO: index users by authid as well as name
            # this would entail checking authid for uniqueness as a key once that key structure starts being built
            authid = secrets.token_bytes(64)
            b64authid = base64.b64encode(authid).decode()
            await cfm.set_user(username, {'webauthid': b64authid})
        opts = registration_request(username, cfm, APP_RELYING_PARTY)
        return opts
    elif url.startswith('/registered_credentials/'):
        username = url.rsplit('/', 1)[-1]
        userinfo = cfm.get_user(username)
        if not isinstance(username, bytes):
            username = username.encode('utf8')
        opts = authentication_request(username, APP_RELYING_PARTY)
        return opts
    elif url.startswith('/validate/'):
        username = url.rsplit('/', 1)[-1]
        userinfo = cfm.get_user(username)
        if not isinstance(username, bytes):
            username = username.encode('utf8')
        req = json.loads(reqbody)
        rsp = authentication_response(req, username, APP_RELYING_PARTY, APP_ORIGIN)
        if rsp == 'Timeout':
            raise Exception('Authentication timed out')
        elif rsp['verified'] and authorized is not None:
            sessinfo = {'username': username}
            if 'authtoken' in authorized:
                sessinfo['authtoken'] = authorized['authtoken']
            if 'sessionid' in authorized:
                sessinfo['sessionid'] = authorized['sessionid']
            if 'username' in rsp and rsp['username']:
                sessinfo['username'] = rsp['username']
            tlvdata.unicode_dictvalues(sessinfo)
            return json.dumps(sessinfo)
        else:
            return rsp
    elif url == '/register_credential':
        req = json.loads(reqbody)
        userinfo = cfm.get_user(username)
        rsp = await registration_response(req, username, APP_RELYING_PARTY, APP_ORIGIN)
        if rsp.get('verified', False):
            return json.dumps({'status': 'Success'})


