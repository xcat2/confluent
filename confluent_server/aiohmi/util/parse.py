# Copyright 2019 Lenovo Corporation
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

from datetime import datetime
from datetime import timedelta

from dateutil import tz


def parse_time(timeval):
    if timeval is None:
        return None
    try:
        if '+' not in timeval and len(timeval.split('-')) <= 3:
            retval = datetime.strptime(timeval, '%Y-%m-%dT%H:%M:%SZ')
            return retval.replace(tzinfo=tz.tzutc())
    except ValueError:
        pass
    try:
        positive = None
        offset = None
        if '+' in timeval:
            timeval, offset = timeval.split('+', 1)
            positive = 1
        elif len(timeval.split('-')) > 3:
            timeval, offset = timeval.rsplit('-', 1)
            positive = -1
        if positive:
            hrs, mins = offset.split(':', 1)
            secs = int(hrs) * 60 + int(mins)
            secs = secs * 60 * positive
            ms = None
            if '.' in timeval:
                # A decimal fraction of a second. Read as whole
                # milliseconds, '.5' came out as five of them.
                timeval, fraction = timeval.split('.', 1)
                ms = timedelta(seconds=float('0.' + fraction))
            retval = datetime.strptime(timeval, '%Y-%m-%dT%H:%M:%S')
            if ms:
                retval += ms
            return retval.replace(tzinfo=tz.tzoffset('', secs))
    except ValueError:
        pass
    try:
        return datetime.strptime(timeval, '%Y-%m-%dT%H:%M:%S')
    except ValueError:
        pass
    try:
        return datetime.strptime(timeval, '%Y-%m-%d')
    except ValueError:
        pass
    try:
        return datetime.strptime(timeval, '%m/%d/%Y')
    except ValueError:
        pass
    return None
