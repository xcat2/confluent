# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2016 Lenovo
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

# This provides the implementation of locating MAC addresses on ethernet
# switches.  It is, essentially, a port of 'MacMap.pm' to confluent.
# However, there are enhancements.
# For one, each switch interrogation is handled in an eventlet 'thread'
# For another, MAC addresses are checked in the dictionary on every
# switch return, rather than waiting for all switches to check in
# (which makes it more responsive when there is a missing or bad switch)
# Also, we track the quantity, actual ifName value, and provide a mechanism
# to detect ambiguous result (e.g. if two matches are found, can log an error
# rather than doing the wrong one, complete with the detected ifName value).
# Further, the map shall be available to all facets of the codebase, not just
# the discovery process, so that the cached data maintenance will pay off
# for direct queries

# Provides support for viewing and processing lldp data for switches

import confluent.exceptions as exc
import confluent.log as log
import confluent.snmputil as snmp
from eventlet.greenpool import GreenPool
import re

# The interesting OIDs are:
# 1.0.8802.1.1.2.1.3.7.1.4 - Lookup of LLDP index id to description
#                            Yet another fun fact, the LLDP port index frequent
#                            does *not* map to ifName, like a sane
#                            implementation would do.  Assume ifName equality
#                            but provide a way for 1.3.6.1.2.1.1 indicated
#                            ids to provide custom functions
#  (1.0.8802.1.1.2.1.3.7.1.2 - theoretically this process is only very useful
#                              if this is '5' meaning 'same as ifName per
#                              802.1AB-2005, however at *least* 7 has
#                              been observed to produce same results
#                              For now we'll optimistically assume
#                              equality to ifName
# 1.0.8802.1.1.2.1.4.1.1 - The information about the remote systems attached
#                            indexed by time index, local port, and an
#                            incrementing value
# 1.0.8802.1.1.2.1.4.1.1.5 - chassis id - in theory might have been useful, in
#                            practice limited as the potential to correlate
#                            to other contexts is limited.  As a result,
#                            our strategy will be to ignore this and focus
#                            instead on bridge-mib/qbridge-mib indicate data
#                            a potential exception would be pulling in things
#                            that are fundamentally network equipment,
#                            where significant ambiguity may exist.
#                            While in a 'host' scenario, there is ambiguity
#                            it is more controlled (virtual machines are given
#                            special treatment, and strategies exist for
#                            disambiguating shared management/data port, and
#                            other functions do not interact with our discovery
#                            framework
# # 1.0.8802.1.1.2.1.4.1.1.9 - SysName - could be handy hint in some scenarios
# # 1.0.8802.1.1.2.1.4.1.1.10 - SysDesc - good stuff


def lenovoname(idx, desc):
    if desc.isdigit():
        return 'Ethernet' + str(idx)
    return desc

nameoverrides = [
    (re.compile('20301\..*'), lenovoname),
]


def _lldpdesc_to_ifname(switchid, idx, desc):
    for tform in nameoverrides:
        if tform[0].match(switchid):
            desc = tform[1](idx, desc)
    return desc


def _extract_neighbor_data_b(args):
    """Build LLDP data about elements connected to switch

    args are carried as a tuple, because of eventlet convenience
    """
    switch, password, user = args
    conn = snmp.Session(switch, password, user)
    sid = None
    lldpdata = {}
    for sysid in conn.walk('1.3.6.1.2.1.1.2'):
        sid = str(sysid[1][6:])
    idxtoifname = {}
    for oidindex in conn.walk('1.0.8802.1.1.2.1.3.7.1.4'):
        idx = oidindex[0][-1]
        idxtoifname[idx] = _lldpdesc_to_ifname(sid, idx, str(oidindex[1]))
    for remotedesc in conn.walk('1.0.8802.1.1.2.1.4.1.1.10'):
        iname = idxtoifname[remotedesc[0][-2]]
        lldpdata[iname] = {'description': str(remotedesc[1])}
    for remotename in conn.walk('1.0.8802.1.1.2.1.4.1.1.9'):
        iname = idxtoifname[remotename[0][-2]]
        if iname not in lldpdata:
            lldpdata[iname] = {}
        lldpdata[iname]['name'] = str(remotename[1])
    for remoteid in conn.walk('1.0.8802.1.1.2.1.4.1.1.5'):
        iname = idxtoifname[remoteid[0][-2]]
        if iname not in lldpdata:
            lldpdata[iname] = {}
        lldpdata[iname]['chassisid'] = str(remoteid[1])
    print(repr(lldpdata))


def _extract_neighbor_data(args):
    try:
        _extract_neighbor_data_b(args)
    except Exception:
        log.logtrace()

if __name__ == '__main__':
    # a quick one-shot test, args are switch and snmpv1 string for now
    # (should do three argument form for snmpv3 test
    import sys
    _extract_neighbor_data((sys.argv[1], sys.argv[2]))
