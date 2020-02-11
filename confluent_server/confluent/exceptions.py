# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 IBM Corporation
# Copyright 2015-2017 Lenovo
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
import json
import msgpack

def deserialize_exc(msg):
    excd = msgpack.unpackb(msg, raw=False)
    if excd[0] == 'Exception':
        return Exception(excd[1])
    if excd[0] not in globals():
        return Exception('Cannot deserialize: {0}'.format(repr(excd)))
    if not issubclass(excd[0], ConfluentException):
        return Exception('Cannot deserialize: {0}'.format(repr(excd)))
    return globals(excd[0])(*excd[1])

class ConfluentException(Exception):
    apierrorcode = 500
    _apierrorstr = 'Unexpected Error'

    def get_error_body(self):
        errstr = ' - '.join((self._apierrorstr, str(self)))
        return json.dumps({'error': errstr })

    def serialize(self):
        return msgpack.packb([self.__class__.__name__, [str(self)]],
                             use_bin_type=False)

    @property
    def apierrorstr(self):
        if str(self):
            return self._apierrorstr + ' - ' + str(self)
        return self._apierrorstr


class NotFoundException(ConfluentException):
    # Something that could be construed as a name was not found
    # basically, picture an http error code 404
    apierrorcode = 404
    _apierrorstr = 'Target not found'


class InvalidArgumentException(ConfluentException):
    # Something from the remote client wasn't correct
    # like http code 400
    apierrorcode = 400
    _apierrorstr = 'Bad Request'


class TargetEndpointUnreachable(ConfluentException):
    # A target system was unavailable.  For example, a BMC
    # was unreachable.  http code 504
    apierrorcode = 504
    _apierrorstr = 'Unreachable Target'


class TargetEndpointBadCredentials(ConfluentException):
    # target was reachable, but authentication/authorization
    # failed
    apierrorcode = 502
    _apierrorstr = 'Bad Credentials'


class LockedCredentials(ConfluentException):
    # A request was performed that required a credential, but the credential
    # store is locked
    _apierrorstr = 'Credential store locked'


class DegradedCollective(ConfluentException):
    # We are in a collective with at least half of the member nodes missing
    _apierrorstr = 'Collective does not have quorum'


class ForbiddenRequest(ConfluentException):
    # The client request is not allowed by authorization engine
    apierrorcode = 403
    _apierrorstr = 'Forbidden'


class NotImplementedException(ConfluentException):
    # The current configuration/plugin is unable to perform
    # the requested task. http code 501
    apierrorcode = 501
    _apierrorstr = '501 - Not Implemented'



class GlobalConfigError(ConfluentException):
    # The configuration in the global config file is not right
    _apierrorstr = 'Global configuration contains an error'


class TargetResourceUnavailable(ConfluentException):
    # This is meant for scenarios like asking to read a sensor that is
    # currently unavailable.  This may be a persistent or transient state
    apierrocode = 503
    _apierrorstr = 'Target Resource Unavailable'

class PubkeyInvalid(ConfluentException):
    apierrorcode = 502
    _apierrorstr = '502 - Invalid certificate or key on target'

    def __init__(self, text, certificate, fingerprint, attribname, event):
        super(PubkeyInvalid, self).__init__(self, text)
        self.myargs = (text, certificate, fingerprint, attribname, event)
        self.fingerprint = fingerprint
        self.attrname = attribname
        self.message = text
        certtxt = base64.b64encode(certificate)
        if not isinstance(certtxt, str):
            certtxt = certtxt.decode('utf8')
        bodydata = {'message': text,
                    'event': event,
                    'fingerprint': fingerprint,
                    'fingerprintfield': attribname,
                    'certificate': certtxt}
        self.errorbody = json.dumps(bodydata)

    def serialize(self):
        return msgpack.packb([self.__class__.__name__, self.myargs],
                             use_bin_type=False)

    def get_error_body(self):
        return self.errorbody

class LoggedOut(ConfluentException):
    apierrorcode = 401
    _apierrorstr = '401 - Logged out'

    def get_error_body(self):
        return '{"loggedout": 1}'
