# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2026 Lenovo
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import hashlib
import hmac
import json
import math
import secrets
import time


_SECRET_ATTRIBUTE = 'secret.apikey'


def _base64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')


def _decode_base64url(value):
    if not isinstance(value, str):
        raise ValueError('Invalid bearer token')
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def _make_jws(username, secret, expiration=None):
    header = {'alg': 'HS256', 'typ': 'JWT'}
    payload = {'sub': username, 'iat': int(time.time())}
    if expiration is not None:
        payload['exp'] = payload['iat'] + int(expiration * 86400)
    encoded_header = _base64url(json.dumps(
        header, separators=(',', ':')).encode('utf8'))
    encoded_payload = _base64url(json.dumps(
        payload, separators=(',', ':')).encode('utf8'))
    signing_input = '{0}.{1}'.format(encoded_header, encoded_payload).encode('ascii')
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return '{0}.{1}'.format(signing_input.decode('ascii'), _base64url(signature))


def _username_string(username):
    if isinstance(username, bytes):
        return username.decode('utf8')
    return str(username)


def _get_expiration(reqbody):
    if not reqbody:
        return None
    if isinstance(reqbody, bytes):
        reqbody = reqbody.decode('utf8')
    try:
        body = json.loads(reqbody)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError('Request body must be JSON')
    if not isinstance(body, dict):
        raise ValueError('Request body must be a JSON object')
    if 'expiration' not in body:
        raise ValueError('expiration is required parameter')
    expiration = body['expiration']
    if not expiration:  # a false-y expiration means opt out of expiration
        return None
    if not isinstance(expiration, (int, float)) or not math.isfinite(expiration) or expiration < 0:
        raise ValueError('Invalid number specified, must be either number of days or false/null')
    return expiration


def validate_bearer_token(token, cfgmgr):
    """Return the token subject when a bearer token is valid."""
    try:
        encoded_header, encoded_payload, encoded_signature = token.split('.')
        header = json.loads(_decode_base64url(encoded_header))
        payload = json.loads(_decode_base64url(encoded_payload))
        signature = _decode_base64url(encoded_signature)
    except (AttributeError, ValueError, UnicodeDecodeError, json.JSONDecodeError,
            TypeError, base64.binascii.Error):
        return None
    if header != {'alg': 'HS256', 'typ': 'JWT'}:
        return None
    username = payload.get('sub')
    if not isinstance(username, str) or not username:
        return None
    expiration = payload.get('exp')
    if expiration is not None and (
            isinstance(expiration, bool) or
            not isinstance(expiration, (int, float)) or
            not math.isfinite(expiration) or expiration <= time.time()):
        return None
    user = cfgmgr.get_user(username, decrypt=True)
    if not user or not user.get(_SECRET_ATTRIBUTE):
        return None
    secret = user[_SECRET_ATTRIBUTE]['value']
    if not isinstance(secret, bytes):
        secret = secret.encode('utf8')
    signing_input = '{0}.{1}'.format(
        encoded_header, encoded_payload).encode('ascii')
    expected = hmac.new(secret, signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        return None
    return username

async def handle_api_request(url, username, cfgmgr, reqbody, method):
    """Handle an authenticated API-key request.

    The HTTP layer supplies the authenticated request context.  The return
    value is a ``(status, payload)`` pair for ``httpapi`` to serialize.
    """
    username = _username_string(username)
    operation = url.removeprefix('/sessions/current/apikey/')
    if method == 'retrieve':
        if operation == 'provisioned':
            user = cfgmgr.get_user(username)
            if not user or not user.get(_SECRET_ATTRIBUTE):
                return 200, {'provisioned': False}
            return 200, {'provisioned': True}
        else:
            return 405, {'error': 'Method Not Allowed'}
    if operation == 'create':
        try:
            expiration = _get_expiration(reqbody)
        except ValueError as error:
            return 400, {'error': str(error)}
        user = cfgmgr.get_user(username, decrypt=True)
        if user is None:
            await cfgmgr.create_user(username, role='Stub')
            user = cfgmgr.get_user(username, decrypt=True)
        secret = user.get(_SECRET_ATTRIBUTE, {}).get('value', None)
        if not secret:
            secret = secrets.token_bytes(32)
            secret = _base64url(secret)
            await cfgmgr.set_user(username, {_SECRET_ATTRIBUTE: secret})
        if isinstance(secret, str):
            secret = secret.encode('utf8')
        return 200, {'jws': _make_jws(username, secret, expiration)}
    if operation == 'provisioned':
        user = cfgmgr.get_user(username)
        if not user or not user.get(_SECRET_ATTRIBUTE):
            return 200, {'provisioned': False}
        return 200, {'provisioned': True}
    if operation == 'revokeall':
        user = cfgmgr.get_user(username, decrypt=True)
        if user is None:
            return 200, {'revoked': True, 'msg': "User doesn't exist"}
        if not user.get(_SECRET_ATTRIBUTE):
            return 200, {'revoked': True, 'msg': "No API keys to revoke"}
        await cfgmgr.set_user(username, {_SECRET_ATTRIBUTE: None})
        return 200, {'revoked': True}
    return 404, {'error': 'Unknown API-key operation'}