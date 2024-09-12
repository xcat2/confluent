from webauthn_rp.registrars import CredentialData
import confluent.tlvdata as tlvdata
import confluent.util as util
import json


import secrets, time
from typing import Any, Optional
from webauthn_rp.backends import CredentialsBackend
from webauthn_rp.builders import *
from webauthn_rp.converters import cose_key, jsonify
from webauthn_rp.errors import WebAuthnRPError
from webauthn_rp.parsers import parse_cose_key, parse_public_key_credential
from webauthn_rp.registrars import *
from webauthn_rp.types import (
    AttestationObject, AttestationType, AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse, AuthenticatorData,
    COSEAlgorithmIdentifier, PublicKeyCredential,
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameters,
    PublicKeyCredentialRpEntity, PublicKeyCredentialType,
    PublicKeyCredentialUserEntity, TrustedPath)


challenges = {}

CONFIG_MANAGER = None

class Credential():
    def __init__(self, id, signature_count, public_key):
        self.id = id
        self.signature_count = signature_count
        self.credential_public_key = public_key 

class Challenge():
    def __init__(self, request, timstamp_ms, id=None) -> None:
        if id is None:
            self.id = util.randomstring(16)
        else:
            self.id = id
        self.request = request
        self.timestamp_ms = timstamp_ms



class User():
    def __init__(self, id, username, user_handle, challenge: Challenge = None, credential: Credential = None):
        self.id = id
        self.username = username
        self.user_handle = user_handle
        self.challenges = challenge 
        self.credentials = credential 

    def __parse_credentials(self): 
        return {"id": self.credentials.id, "signature_count": self.credentials.signature_count, "credential_public_key": self.credentials.credential_public_key} 


    def __parse_challenges(self):
        return {"id": self.challenges.id, 'request': self.challenges.request, 'timestamp_ms': self.challenges.timestamp_ms}


    @staticmethod
    def seek_credential_by_id(credential_id):
        """
        There certainly is a better way to do this but for now lets try the wrong way that works 
        """
        for username in CONFIG_MANAGER.list_users():
            authenticators = CONFIG_MANAGER.get_user(username).get('authenticators', {})
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
        try:
            credential = authenticators['credentials']       
        except KeyError:
            return None
        if credential_id is None:
                return Credential(id=credential["id"], signature_count=credential["signature_count"], public_key=credential["credential_public_key"])
        if credential["id"] == credential_id:
            return Credential(id=credential["id"], signature_count=credential["signature_count"], public_key=credential["credential_public_key"])

        return None
    
    @staticmethod
    def get_challenge(challengeID, username):
        if not isinstance(username, str):
            username = username.decode('utf8')
        authenticators = CONFIG_MANAGER.get_user(username).get('authenticators', {})
        challenge = authenticators['challenges']
        if challenge["id"] == challengeID:
            return Challenge(request=challenge["request"], timstamp_ms=challenge["timestamp_ms"], id=challenge["id"])
      
        return None

    @staticmethod
    def get(username):
        if not CONFIG_MANAGER:
            raise Exception('config manager is not set up')
        if not isinstance(username, str):
            username = username.decode('utf8')
        userinfo = CONFIG_MANAGER.get_user(username)
        authenticators = CONFIG_MANAGER.get_user(username).get('authenticators', {})
        if userinfo is None:
            return None
        authid = userinfo.get('webauthid', None)
        challenge = authenticators.get("challenges", None)
        challenges_return = Challenge(challenge['request'], challenge['timestamp_ms'], id=challenge["id"])
      
        credential = authenticators.get("credentials", None)
        credentials_return = (Credential(credential['id'], credential['signature_count'], credential["credential_public_key"]))
       
        return User(id=None, username=username, user_handle=authid, challenge=challenges_return, credential=credentials_return)

    def save(self):
        authenticators = CONFIG_MANAGER.get_user(self.username).get('authenticators', {})
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


def timestamp_ms():
    return int(time.time() * 1000)


class RegistrarImpl(CredentialsRegistrar):
    def register_credential_attestation(
            self, 
            credential: PublicKeyCredential, 
            att: AttestationObject, 
            att_type: AttestationType, 
            user: PublicKeyCredentialUserEntity, 
            rp: PublicKeyCredentialRpEntity, 
            trusted_path: Optional[TrustedPath] = None) -> Any:
        
        assert att.auth_data is not None
        assert att.auth_data.attested_credential_data is not None
        cpk = att.auth_data.attested_credential_data.credential_public_key

        user_model = User.get(user.name)
        if user_model is None:
            return 'No user found'
        
        credential_model = Credential(id=credential.raw_id, signature_count=None, public_key=cose_key(cpk))
        user_model.add(credential_model)
        user_model.save()
    
    def register_credential_assertion(
            self, 
            credential: PublicKeyCredential, 
            authenticator_data: AuthenticatorData, 
            user: PublicKeyCredentialUserEntity, 
            rp: PublicKeyCredentialRpEntity) -> Any:
        
        user_model = User.get(user.name)
        credential_model = User.get_credential(credential_id=credential.raw_id, username=user.name)
        credential_model.signature_count = None
        user_model.update(credential_model)
        user_model.save()

    def get_credential_data(
            self, 
            credential_id: bytes) -> Optional[CredentialData]:

        #credential_model = User.get_credential(credential_id=credential_id, username=username)
        (credential_model, username) = User.seek_credential_by_id(credential_id)
        user_model = User.get(username)

        return CredentialData(
            parse_cose_key(credential_model.credential_public_key),
            credential_model.signature_count,
            PublicKeyCredentialUserEntity(
                name=user_model.username,
                id=user_model.user_handle,
                display_name=user_model.username
            )
        )
    

APP_ORIGIN = 'https://ndiamai'
APP_TIMEOUT = 60000
APP_RELYING_PARTY = PublicKeyCredentialRpEntity(name='Confluent Web UI', id="ndiamai")

APP_CCO_BUILDER = CredentialCreationOptionsBuilder(
    rp=APP_RELYING_PARTY,
    pub_key_cred_params=[
        PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY,
                                      alg=COSEAlgorithmIdentifier.Value.ES256)
    ],
    timeout=APP_TIMEOUT,
)

APP_CRO_BUILDER = CredentialRequestOptionsBuilder(
    rp_id=APP_RELYING_PARTY.id,
    timeout=APP_TIMEOUT,
)

APP_CREDENTIALS_BACKEND = CredentialsBackend(RegistrarImpl())

def registration_request(username, cfg):
    user_model = User.get(username)
    if user_model is None:
        raise Exception("User not foud")
    
    challenge_bytes = secrets.token_bytes(64)
    challenge = Challenge(request=challenge_bytes, timstamp_ms=timestamp_ms())
    user_model.add(challenge)
    user_model.save()

    options = APP_CCO_BUILDER.build(
        user=PublicKeyCredentialUserEntity(
            name=username,
            id=user_model.user_handle,
            display_name=username
        ),
        challenge=challenge_bytes
    )

    options_json = jsonify(options)
    return {
        'challengeID': challenge.id,
        'creationOptions': options_json
    }

def registration_response(request, username):
    try:
        challengeID = request["challengeID"]
        credential = parse_public_key_credential(json.loads(request["credential"]))
    except Exception:
        raise Exception("Could not parse input data")
    
    if type(credential.response) is not AuthenticatorAttestationResponse:
        raise Exception("Invalid response type")
    
    challenge_model = User.get_challenge(challengeID, username)
    if not challenge_model:
        raise Exception("Could not find challenge matching given id")

    user_model = User.get(username)
    if not user_model:
        raise Exception("Invalid Username")
    
    current_timestamp = timestamp_ms()
    if current_timestamp - challenge_model.timestamp_ms > APP_TIMEOUT:
        return "Timeout"
    
    
    user_entity = PublicKeyCredentialUserEntity(name=user_model.username, id=user_model.user_handle, display_name=user_model.username)
    try:
        APP_CREDENTIALS_BACKEND.handle_credential_attestation(
            credential=credential,
            user=user_entity,
            rp=APP_RELYING_PARTY,
            expected_challenge=challenge_model.request,
            expected_origin=APP_ORIGIN
        )
    except WebAuthnRPError:
        raise Exception("Could not handle credential attestation")
    
    return True


def authentication_request(username):
    user_model = User.get(username)

    if user_model is None:
        return 'User not registered'
    
    credential = user_model.get_credential(None, username)
    print(credential)
    if credential is None:
        return f'No credential for User found {username}'
    
    challenge_bytes = secrets.token_bytes(64)
    challenge = Challenge(request=challenge_bytes, timstamp_ms=timestamp_ms())
    user_model.add(challenge)
    user_model.save()

    options = APP_CRO_BUILDER.build(
        challenge=challenge_bytes,
        allow_credentials=[
            PublicKeyCredentialDescriptor(
               id=credential.id,
               type=PublicKeyCredentialType.PUBLIC_KEY
            )
        ]
    )

    options_json = jsonify(options)
    return {
        'challengeID': challenge.id,
        'requestOptions': options_json
    }

def authentication_response(request, username):
    try:
        challengeID = request["challengeID"]
        credential = parse_public_key_credential(json.loads(request["credential"]))
    except Exception:
        raise Exception("Could not parse input data")
    
    if type(credential.response) is not AuthenticatorAssertionResponse:
        raise Exception('Invalid response type')
    
    challenge_model = User.get_challenge(challengeID, username)
    if not challenge_model:
        raise Exception("Could not find challenge matching given id")

    user_model = User.get(username)
    if not user_model:
        raise Exception("Invalid Username")
    
    current_timestamp = timestamp_ms()
    if current_timestamp - challenge_model.timestamp_ms > APP_TIMEOUT:
        return "Timeout"
    
    user_entity = PublicKeyCredentialUserEntity(name=user_model.username, id=user_model.user_handle, display_name=user_model.username)

    try:
        APP_CREDENTIALS_BACKEND.handle_credential_assertion(
            credential=credential,
            user=user_entity,
            rp=APP_RELYING_PARTY,
            expected_challenge=challenge_model.request,
            expected_origin=APP_ORIGIN
        )
    except WebAuthnRPError:
        raise Exception('Could not handle credential assertion')
    
    return {"verified": True}
    
    

def handle_api_request(url, env, start_response, username, cfm, headers, reqbody, authorized):
    """
        For now webauth is going to be limited to just one passkey per user 
        If you try to register a new passkey this will just clear the old one and regist the new passkey
    """
    global CONFIG_MANAGER
    CONFIG_MANAGER = cfm
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
            cfm.set_user(username, {'webauthid': authid})
        opts = registration_request(username, cfm)
        start_response('200 OK', headers)
        yield json.dumps(opts)
    elif url.startswith('/registered_credentials/'):
        username = url.rsplit('/', 1)[-1]
        userinfo = cfm.get_user(username)
        if not isinstance(username, bytes):
            username = username.encode('utf8')
        opts = authentication_request(username)
        start_response('200 OK', headers)
        yield json.dumps(opts)
    elif url.startswith('/validate/'):
        username = url.rsplit('/', 1)[-1]
        userinfo = cfm.get_user(username)
        if not isinstance(username, bytes):
            username = username.encode('utf8')
        req = json.loads(reqbody)
        rsp = authentication_response(req, username)
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
        rsp = registration_response(req, username)
        if rsp == 'Timeout':
            start_response('408 Timeout', headers)
        else:
            print('worked out')
            start_response('200 OK', headers)
            yield json.dumps({'status': 'Success'})


