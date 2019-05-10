# Copyright 2017-2019 Lenovo
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

import confluent.discovery.handlers.imm as immhandler
import confluent.util as util
import pyghmi.exceptions as pygexc
import pyghmi.ipmi.oem.lenovo.imm as imm




class NodeHandler(immhandler.NodeHandler):
    devname = 'XCC'

    @classmethod
    def adequate(cls, info):
        # We can sometimes receive a partially initialized SLP packet
        # This is not adequate for being satisfied
        return bool(info.get('attributes', {}))

    def preconfig(self):
        ff = self.info.get('attributes', {}).get('enclosure-form-factor', '')
        if ff not in ('dense-computing', [u'dense-computing']):
            return
        self.trieddefault = None  # Reset state on a preconfig attempt
        # attempt to enable SMM
        #it's normal to get a 'not supported' (193) for systems without an SMM
        ipmicmd = None
        try:
            ipmicmd = self._get_ipmicmd()
            ipmicmd.xraw_command(netfn=0x3a, command=0xf1, data=(1,))
        except pygexc.IpmiException as e:
            if (e.ipmicode != 193 and 'Unauthorized name' not in str(e) and
                    'Incorrect password' not in str(e)):
                # raise an issue if anything other than to be expected
                raise
            self.trieddefault = True
        #TODO: decide how to clean out if important
        #as it stands, this can step on itself
        #if ipmicmd:
        #    ipmicmd.ipmi_session.logout()

    def validate_cert(self, certificate):
        # broadly speaking, merely checks consistency moment to moment,
        # but if https_cert gets stricter, this check means something
        fprint = util.get_fingerprint(self.https_cert)
        return util.cert_matches(fprint, certificate)

    def set_password_policy(self, ic):
        ruleset = {'USER_GlobalMinPassChgInt': '0'}
        for rule in self.ruleset.split(','):
            if '=' not in rule:
                continue
            name, value = rule.split('=')
            if value.lower() in ('no', 'none', 'disable', 'disabled'):
                value = '0'
            if name.lower() in ('expiry', 'expiration'):
                ruleset['USER_GlobalPassExpPeriod'] = value
                if int(value) < 5:
                    ruleset['USER_GlobalPassExpWarningPeriod'] = value
            if name.lower() in ('lockout', 'loginfailures'):
                if value.lower() in ('no', 'none', 'disable', 'disabled'):
                    value = '0'
                ruleset['USER_GlobalMaxLoginFailures'] = value
            if name.lower() == 'complexity':
                ruleset['USER_GlobalPassComplexRequired'] = value
            if name.lower() == 'reuse':
                ruleset['USER_GlobalMinPassReuseCycle'] = value
        ic.register_key_handler(self.validate_cert)
        ic.oem_init()
        try:
            ic._oem.immhandler.wc.grab_json_response('/api/dataset', ruleset)
        except Exception as e:
            print(repr(e))
            pass

    def config(self, nodename, reset=False):
        # TODO(jjohnson2): set ip parameters, user/pass, alert cfg maybe
        # In general, try to use https automation, to make it consistent
        # between hypothetical secure path and today.
        dpp = self.configmanager.get_node_attributes(
            nodename, 'discovery.passwordrules')
        self.ruleset = dpp.get(nodename, {}).get(
            'discovery.passwordrules', {}).get('value', '')
        ic = self._bmcconfig(nodename, customconfig=self.set_password_policy)
        ff = self.info.get('attributes', {}).get('enclosure-form-factor', '')
        if ff not in ('dense-computing', [u'dense-computing']):
            return
        # Ok, we can get the enclosure uuid now..
        enclosureuuid = ic._oem.immhandler.get_property(
            '/v2/ibmc/smm/chassis/uuid')
        if enclosureuuid:
            enclosureuuid = imm.fixup_uuid(enclosureuuid).lower()
            em = self.configmanager.get_node_attributes(nodename,
                                                        'enclosure.manager')
            em = em.get(nodename, {}).get('enclosure.manager', {}).get(
                'value', None)
            # ok, set the uuid of the manager...
            if em:
                self.configmanager.set_node_attributes(
                    {em: {'id.uuid': enclosureuuid}})

# TODO(jjohnson2): web based init config for future prevalidated cert scheme
#    def config(self, nodename):
#        return

