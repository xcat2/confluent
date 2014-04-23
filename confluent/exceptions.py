# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 IBM Corporation
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


class ConfluentException(Exception):
    pass


class NotFoundException(ConfluentException):
    # Something that could be construed as a name was not found
    # basically, picture an http error code 404
    pass


class InvalidArgumentException(ConfluentException):
    # Something from the remote client wasn't correct
    # like http code 400
    pass


class TargetEndpointUnreachable(ConfluentException):
    # A target system was unavailable.  For example, a BMC
    # was unreachable.  http code 504
    pass

class TargetEndpointBadCredentials(ConfluentException):
    # target was reachable, but authentication/authorization
    # failed
    pass


class ForbiddenRequest(ConfluentException):
    # The client request is not allowed by authorization engine
    pass
