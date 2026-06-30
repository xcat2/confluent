# Copyright 2026 MEGWARE Computer Vertrieb und Service GmbH
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

"""
OEM handler for Megware EUREKA chassis Redfish service.

The EUREKA chassis is a software-only Redfish service (not a BMC).
It manages up to 12 nodes with individual BMCs and up to 10 PSUs.
"""

import aiohmi.redfish.oem.generic as generic
import aiohmi.exceptions as exc
import aiohmi.constants as const


class OEMHandler(generic.OEMHandler):
    usegenericsensors = True

    async def get_default_sysurl(self):
        """Return the system URL for the first available node.

        The EUREKA enclosure has up to 12 nodes (Node1-Node12).
        Returns the first enabled/inserted node, or the first node overall.
        """
        if not self._varsysurl and 'Systems' in self._rootinfo:
            systems = self._rootinfo['Systems']['@odata.id']
            res = await self.webclient.grab_json_response_with_status(systems)
            if res[1] == 401:
                raise exc.PyghmiException('Access Denied')
            elif res[1] < 200 or res[1] >= 300:
                raise exc.PyghmiException(repr(res[0]))
            members = res[0].get('Members', [])
            if len(members) == 1:
                self._varsysurl = members[0]['@odata.id']
            elif len(members) > 1:
                for member in members:
                    murlinfo, status = await self.webclient.grab_json_response_with_status(
                        member['@odata.id'])
                    if status == 200:
                        if murlinfo.get('Status', {}).get('State') == 'Enabled':
                            self._varsysurl = member['@odata.id']
                            break
                if not self._varsysurl:
                    self._varsysurl = members[0]['@odata.id']
        return self._varsysurl

    async def get_system_power_watts(self, fishclient):
        """Read node input power from EUREKA sensor endpoints.

        The EUREKA chassis reports node power via Node{N}InputPower
        sensors under /redfish/v1/Chassis/1/Sensors/ rather than
        standard Redfish PowerControl.
        """
        totalwatts = 0
        gotpower = False
        for sysurl in self._allsysurls:
            nodeid = sysurl.rstrip('/').rsplit('/', 1)[-1]
            nodeid = nodeid.replace('Node', '')
            if not nodeid.isdigit():
                continue
            try:
                sensor_url = '/redfish/v1/Chassis/1/Sensors/Node{}InputPower'.format(nodeid)
                sensor = await fishclient._do_web_request(sensor_url)
                if sensor and 'Reading' in sensor:
                    totalwatts += float(sensor['Reading'])
                    gotpower = True
            except Exception:
                pass
        if not gotpower:
            raise exc.UnsupportedFunctionality(
                'Node power sensors not available')
        return totalwatts

    async def _get_cpu_temps(self, fishclient):
        """Read CPU temperatures from EUREKA BMC sensor endpoints.

        Reads BMC{N}CPU0Temp and BMC{N}CPU1Temp sensors from
        /redfish/v1/Chassis/1/Sensors/.
        """
        cputemps = []
        for sysurl in self._allsysurls:
            nodeid = sysurl.rstrip('/').rsplit('/', 1)[-1]
            nodeid = nodeid.replace('Node', '')
            if not nodeid.isdigit():
                continue
            for cpu in ('CPU0', 'CPU1'):
                try:
                    sensor_url = '/redfish/v1/Chassis/1/Sensors/BMC{}Cpu{}Temp'.format(nodeid, cpu)
                    sensor = await fishclient._do_web_request(sensor_url)
                    if sensor and 'Reading' in sensor:
                        cputemps.append({
                            'name': 'CPU {} Node {}'.format(cpu, nodeid),
                            'value': float(sensor['Reading']),
                            'state_ids': [],
                            'units': const.SensorUnits.Celsius,
                            'imprecision': None,
                        })
                except Exception:
                    pass
        return cputemps

    async def reseat_bay(self, bay):
        """Power cycle a specific node in the EUREKA enclosure.

        Uses ComputerSystem.Reset with ForceRestart on the target node.
        bay=-1 (enclosure-level) is not supported.
        """
        if bay == -1:
            raise exc.UnsupportedFunctionality(
                'Enclosure-level reset is not supported')
        nodeurl = '/redfish/v1/Systems/Node{}'.format(bay)
        await self._do_web_request(
            nodeurl + '/Actions/ComputerSystem.Reset',
            {'ResetType': 'ForceRestart'},
            method='POST')

    async def get_health(self, fishclient, verbose=True):
        """Gather health status for the EUREKA chassis and all nodes."""
        issues = []
        try:
            chassis = await self._do_web_request('/redfish/v1/Chassis/1')
            health = chassis.get('Status', {}).get('Health', 'OK')
            if health != 'OK':
                issues.append('Chassis health: {}'.format(health))
        except Exception:
            issues.append('Cannot reach chassis health endpoint')

        for sysurl in self._allsysurls:
            try:
                sysinfo = await self._do_web_request(sysurl)
            except Exception:
                continue
            state = sysinfo.get('Status', {}).get('State', 'Absent')
            name = sysurl.rstrip('/').rsplit('/', 1)[-1]
            if state == 'Absent':
                issues.append('{}: Absent'.format(name))
            elif state != 'Enabled':
                issues.append('{}: {}'.format(name, state))

        health = 0
        if issues:
            health = 1
        return {'badreadings': [], 'health': health}
