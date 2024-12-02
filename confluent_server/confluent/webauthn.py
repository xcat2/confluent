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
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
)

from webauthn import verify_registration_response
from webauthn import verify_authentication_response


challenges = {}

CONFIG_MANAGER = None

class Credential():
    def __init__(self, id, signature_count, public_key):
        self.id = id
        self.signature_count = signature_count
        self.credential_public_key = public_key 

class Challenge():
    def __init__(self, request, id=None) -> None:
        if id is None:
            self.id = util.randomstring(16)
        else:
            self.id = id
        self.request = request

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
    def __init__(self, id, username, user_handle, challenge: Challenge = None, credential: Credential = None):
        self.id = id
        self.username = username
        self.user_handle = user_handle
        self.challenges = challenge 
        self.credentials = credential 

    def __parse_credentials(self): 
        if self.credentials:
            credid = base64.b64encode(self.credentials.id).decode()
            pubkey = base64.b64encode(self.credentials.credential_public_key).decode()
            return {"id": credid, "signature_count": self.credentials.signature_count, "credential_public_key": pubkey}


    def __parse_challenges(self):
        if self.challenges:
            request = base64.b64encode(self.challenges.request).decode()
            return {"id": self.challenges.id, 'request': request}


    @staticmethod
    def seek_credential_by_id(credential_id):
        """
        There certainly is a better way to do this but for now lets try the wrong way that works 
        """
        for username in CONFIG_MANAGER.list_users():
            authenticators = CONFIG_MANAGER.get_user(username).get('authenticators', {})
            authenticators = _load_authenticators(authenticators)
            try:
                credential = authenticators['credentials']
            except KeyError:
                continue
            if "id" in credential.keys() and credential["id"] == credential_id:
                #for now leaving signature count as None
                return (Credential(id=credential["id"], signature_count=None, public_key=credential["credential_public_key"]), username)
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
                return Credential(id=credential["id"], signature_count=credential["signature_count"], public_key=credential["credential_public_key"])

        return None
    
    @staticmethod
    def get_challenge(username):
        if not isinstance(username, str):
            username = username.decode('utf8')
        authuser = CONFIG_MANAGER.get_user(username)
        if not authuser:
            return None
        authenticators = authuser.get('authenticators', {})
        authenticators = _load_authenticators(authenticators)
        challenge = authenticators['challenges']
        return Challenge(request=challenge["request"], id=challenge["id"])


    @staticmethod
    def get(username):
        challenges_return = None
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
        challenge = authenticators.get("challenges", None)
        if challenge:
            challenges_return = Challenge(challenge['request'], id=challenge["id"])

        credential = authenticators.get("credentials", None)
        if credential:
            credentials_return = (Credential(credential['id'], credential['signature_count'], credential["credential_public_key"]))
       
        return User(id=None, username=username, user_handle=authid, challenge=challenges_return, credential=credentials_return)

    def save(self):
        authenticators = CONFIG_MANAGER.get_user(self.username).get('authenticators', {})
        authenticators = _load_authenticators(authenticators)
        authenticators['challenges'] = self.__parse_challenges()  # Looks like the bigger the array we encounter problems changing to just save one challenge
        authenticators['credentials'] = self.__parse_credentials()
        
        CONFIG_MANAGER.set_user(self.username, {'authenticators': authenticators})


    def add(self, item):
        if isinstance(item, Challenge):
            self.challenges = item
        elif isinstance(item, Credential):
            self.credentials = item
    
    def update(self, item):
        if isinstance(item, Challenge):
            self.challenges = item
        elif isinstance(item, Credential):
            self.credentials = item
            return
            #raise Exception("Credential item not found")


def registration_request(username, cfg, APP_RELYING_PARTY):
    user_model = User.get(username)
    if user_model is None:
        raise Exception("User not foud")

    options = generate_registration_options(
        rp_name=APP_RELYING_PARTY.name,
        rp_id=APP_RELYING_PARTY.id,
        user_id=user_model.user_handle,
        user_name=username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )

    challenge = Challenge(options.challenge)
    user_model.add(challenge)
    user_model.save()
    options_json = options_to_json(options)
    return options_json


def registration_response(request, username, APP_RELYING_PARTY, APP_ORIGIN):
    challenge_model = User.get_challenge(username)
    if not challenge_model:
        raise Exception("Could not find challenge matching given id")

    user_model = User.get(username)
    if not user_model:
        raise Exception("Invalid Username")

    try:
        registration_verification = verify_registration_response(
        credential=request,
        expected_challenge=challenge_model.request,
        expected_rp_id=APP_RELYING_PARTY.id,
        expected_origin=APP_ORIGIN,
        require_user_verification=True,
        )
    except Exception as err:
        raise Exception("Could not handle credential attestation")
    
    credential = Credential(id=registration_verification.credential_id, signature_count=registration_verification.sign_count, public_key=registration_verification.credential_public_key)
    user_model.add(credential)
    user_model.save()

    return {"verified": True}


def authentication_request(username, APP_RELYING_PARTY):
    user_model = User.get(username)
    if not user_model:
        raise Exception("Invalid Username")

    options = generate_authentication_options(
        rp_id=APP_RELYING_PARTY.id,
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    challenge = Challenge(options.challenge)
    user_model.add(challenge)
    user_model.save()
    opts = options_to_json(options)
    return opts

def authentication_response(request, username, APP_RELYING_PARTY, APP_ORIGIN):
    user_model = User.get(username)
    if not user_model:
        raise Exception("Invalid Username")

    challenge_model = User.get_challenge(username)
    if not challenge_model:
        raise Exception("Could not find challenge matching given id")

    credential_model = User.get_credential(credential_id=None, username=username)
    if not credential_model:
        raise Exception("No credential for user")
    
    verification = verify_authentication_response(
        credential=request,
        expected_challenge=challenge_model.request,
        expected_rp_id=APP_RELYING_PARTY.id,
        expected_origin=APP_ORIGIN,
        credential_public_key = credential_model.credential_public_key,
        credential_current_sign_count = 0,
        require_user_verification = True

    )

    return {"verified": True}
    
class RpEntity(object):
    def __init__(self, name, id):
        self.name = name
        self.id = id 

def handle_api_request(url, env, start_response, username, cfm, headers, reqbody, authorized):
    """
        For now webauth is going to be limited to just one passkey per user 
        If you try to register a new passkey this will just clear the old one and register the new passkey
    """
    global CONFIG_MANAGER
    CONFIG_MANAGER = cfm

    APP_ORIGIN = 'https://' + env['HTTP_X_FORWARDED_HOST']
    HOST = env['HTTP_X_FORWARDED_HOST']
    APP_RELYING_PARTY = RpEntity(name='Confluent Web UI', id=HOST)

    if env['REQUEST_METHOD'] != 'POST':
        raise Exception('Only POST supported for webauthn operations')
    url = url.replace('/sessions/current/webauthn', '')
    if url == '/registration_options':
        userinfo = cfm.get_user(username)
        if not userinfo:
            cfm.create_user(username, role='Stub')
            userinfo = cfm.get_user(username)
        authid = userinfo.get('webauthid', None)
        if not authid:
            authid = secrets.token_bytes(64)
            b64authid = base64.b64encode(authid).decode()
            cfm.set_user(username, {'webauthid': b64authid})
        opts = registration_request(username, cfm, APP_RELYING_PARTY)
        start_response('200 OK', headers)
        yield opts
    elif url.startswith('/registered_credentials/'):
        username = url.rsplit('/', 1)[-1]
        userinfo = cfm.get_user(username)
        if not isinstance(username, bytes):
            username = username.encode('utf8')
        opts = authentication_request(username, APP_RELYING_PARTY)
        start_response('200 OK', headers)
        yield opts
    elif url.startswith('/validate/'):
        username = url.rsplit('/', 1)[-1]
        userinfo = cfm.get_user(username)
        if not isinstance(username, bytes):
            username = username.encode('utf8')
        req = json.loads(reqbody)
        rsp = authentication_response(req, username, APP_RELYING_PARTY, APP_ORIGIN)
        if rsp == 'Timeout':
            start_response('408 Timeout', headers)
        elif rsp['verified'] and start_response:
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
        req = json.loads(reqbody)
        userinfo = cfm.get_user(username)
        if not isinstance(username, bytes):
            username = username.encode('utf8')
        rsp = registration_response(req, username, APP_RELYING_PARTY, APP_ORIGIN)
        if rsp.get('verified', False):
            start_response('200 OK', headers)
            yield json.dumps({'status': 'Success'})


