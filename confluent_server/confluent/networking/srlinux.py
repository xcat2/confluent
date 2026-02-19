import asyncio
import confluent.util as util
import aiohmi.util.webclient as webclient



class SRLinuxClient:
    def __init__(self, switch, user, password, configmanager):
        self.cachedurls = {}
        self.switch = switch
        if configmanager:
            cv = util.TLSCertVerifier(
                configmanager, switch, 'pubkeys.tls_hardwaremanager'
            ).verify_cert
        else:
            cv = lambda x: True
        self.user = user
        self.password = password
        try:
            self.user = self.user.decode()
            self.password = self.password.decode()
        except Exception:
            pass
        self.wc = webclient.SecureHTTPConnection(switch, port=443, verifycallback=cv)
        self.wc.set_basic_credentials(self.user, self.password)
        self.rpc_id = 1

    async def login(self):
        # Just a quick query to validate that credentials are correct and device is reachable and TLS works out however it is supposed to
        await self._get_state('/system/information')

        
        

    async def _rpc_call(self, method, params=None):
        """Make a JSON-RPC call to SR-Linux"""
        payload = {
            'jsonrpc': '2.0',
            'id': self.rpc_id,
            'method': method,
        }
        if params:
            payload['params'] = params
        
        self.rpc_id += 1
        
        rsp = await self.wc.grab_json_response_with_status('/jsonrpc', payload)
        if rsp[1] != 200:
            raise Exception(f"Failed RPC call: {method}, status: {rsp[1]}")
        
        result = rsp[0]
        if 'error' in result:
            raise Exception(f"RPC error: {result['error']}")
        
        return result.get('result', {})

    async def _get_state(self, path, datastore='state'):
        """Get state data from SR-Linux using JSON-RPC get method"""
        params = {
            'commands': [
                {
                    'path': path,
                    'datastore': datastore
                }
            ]
        }
        result = await self._rpc_call('get', params)
        return result

    async def get_firmware(self):
        """Get firmware/software version information"""
        firmdata = {}
        result = await self._get_state('/system/information')
        for item in result:
            if 'version' in item:
                firmdata['SR-Linux'] = {'version': item['version']}
            if 'build-date' in item:
                if 'SR-Linux' in firmdata:
                        firmdata['SR-Linux']['date'] = item['build-date']
        return firmdata

    async def get_sensors(self):
        """Get sensor readings from the device"""
        sensedata = []
        result = await self._get_state('/platform/control/temperature')
        for item in result:
            for pcc in item:
                currreading = {}
                for reading in item[pcc]:
                    if reading.get('temperature', {}).get('alarm-status', False):
                        currreading['health'] = 'critical'
                    else:
                        currreading['health'] = 'ok'
                    states = []
                    if reading.get('oper-state', 'up',) != 'up':
                        states = [reading.get('oper-reason', 'unknown')]
                    currreading['states'] = states
                    currreading['name'] = 'Slot {} Temperature'.format(reading.get('slot', 'Unknown'))
                    currreading['value'] = reading.get('temperature', {}).get('instant', 'Unknown')
                    currreading['units'] = '°C'
                    sensedata.append(currreading)

        result = await self._get_state('/platform/fan-tray')
        for item in result:
            for pft in item:
                currreading = {}
                for reading in item[pft]:
                    if reading.get('srl_nokia-platform-healthz:healthz', {}).get('status', 'healthy') != 'healthy':
                        currreading['health'] = 'critical'
                    else:
                        currreading['health'] = 'ok'
                    states = []
                    if reading.get('oper-state', 'up',) != 'up':
                        states = [reading.get('oper-reason', 'unknown')]
                    currreading['states'] = states
                    currreading['name'] = 'Fan Tray {}'.format(reading.get('id', 'Unknown'))
                    currreading['value'] = reading.get('fan', {}).get('speed', 'Unknown')
                    currreading['units'] = '%'
                    sensedata.append(currreading)

        result = await self._get_state('/platform/power-supply')
        for item in result:
            for pps in item:
                for reading in item[pps]:
                    currreading = {}
                    if reading.get('srl_nokia-platform-healthz:healthz', {}).get('status', 'healthy') != 'healthy':
                        currreading['health'] = 'critical'
                    else:
                        currreading['health'] = 'ok'
                    states = []
                    if reading.get('oper-state', 'up',) != 'up':
                        states = [reading.get('oper-reason', 'unknown')]
                    currreading['states'] = states
                    currreading['name'] = 'Power Supply {} Health'.format(reading.get('id', 'Unknown'))
                    sensedata.append(currreading)
                    tempreading = {'health': 'ok'}
                    tempreading['name'] = 'Power Supply {} Temperature'.format(reading.get('id', 'Unknown'))
                    tempreading['value'] = reading.get('temperature', {}).get('instant', 'Unknown')
                    tempreading['units'] = '°C'
                    sensedata.append(tempreading)
                    for powstat in 'current', 'power', 'voltage':
                        powreading = {'health': 'ok'}
                        powreading['name'] = 'Power Supply {} {}'.format(reading.get('id', 'Unknown'), powstat.capitalize())
                        powreading['value'] = reading.get('input', {}).get(powstat, 'Unknown')
                        if powstat == 'current':
                            powreading['units'] = 'A'
                        elif powstat == 'power':
                            powreading['units'] = 'W'
                        elif powstat == 'voltage':
                            powreading['units'] = 'V'
                        sensedata.append(powreading)
        return sensedata



    async def get_health(self):
        healthdata = {'health': 'ok', 'sensors': []}
        sensors = await self.get_sensors()
        
        for sensor in sensors:
            currhealth = sensor.get('health', 'ok')
            if currhealth != 'ok':
                healthdata['sensors'].append(sensor)
                if sensor['health'] == 'critical':
                    healthdata['health'] = 'critical'
                elif sensor['health'] == 'warning' and healthdata['health'] != 'critical':
                    healthdata['health'] = 'warning'
        
        return healthdata

    async def get_inventory(self):
        invdata = []        
        results = await self._get_state('/platform/chassis')
        for result in results:
            invinfo = {'name': 'System', 'present': True}
            invinfo['information'] = {'Manufacturer': 'Nokia'}
            
            if isinstance(result, dict):
                for key, value in result.items():
                    if key == 'serial-number':
                        invinfo['information']['Serial Number'] = value
                    elif key == 'part-number':
                        invinfo['information']['Part Number'] = value
                    elif key == 'type':
                        invinfo['information']['Model'] = value
            
            if invinfo['information']:
                invdata.append(invinfo)
        return invdata

    async def get_mac_table(self):
        macdict = {}
        response = await self._get_state('/network-instance/bridge-table/mac-table/mac')
        for datum in response:
            for niname in datum:
                for nin in datum[niname]:
                    btable = nin.get('bridge-table', {})
                    for btab in btable:
                        macs = btable[btab].get('mac', [])
                        for macent in macs:
                            macaddr = macent.get('address', None)
                            if macaddr:
                                macport = macent.get('destination', None)
                                if macport:
                                    macdict.setdefault(macport, []).append(macaddr)
        return macdict

    async def get_lldp(self):
        lldpbyport = {}
        
        response = await self._get_state('/system/lldp/interface')
        for datum in response:
            for intfname in datum:
                lldpallinfo = datum[intfname]
                for lldpdatum in lldpallinfo:
                    myportname = lldpdatum.get('name', None)
                    for neighinfo in lldpdatum.get('neighbor', []):
                        peerdesc = neighinfo.get('system-description', 'Unknown')
                        peername = neighinfo.get('system-name', 'Unknown')
                        peerchassisid = neighinfo.get('chassis-id', 'Unknown')
                        peerportid = neighinfo.get('port-id', 'Unknown')
                        lldpinfo = {
                            'verified': True, # Data provided with authentication over TLS
                            'peerdescription': peerdesc,
                            'peername': peername,
                            'peerchassisid': peerchassisid,
                            'peerportid': peerportid,
                            'portid': myportname,
                            'port': myportname,
                        }
                        lldpbyport[myportname] = lldpinfo
        return lldpbyport


async def main():
    import sys
    import os
    from pprint import pprint
    myuser = os.environ.get('SWITCHUSER')
    mypass = os.environ.get('SWITCHPASS')
    if not myuser or not mypass:
        print("Set SWITCHUSER and SWITCHPASS environment variables")
        sys.exit(1)
    
    srl = SRLinuxClient(sys.argv[1], myuser, mypass, None)
    await srl.login()
    pprint(await srl.get_firmware())
    pprint(await srl.get_inventory())
    pprint(await srl.get_sensors())
    pprint(await srl.get_health())
    pprint(await srl.get_lldp())
    pprint(await srl.get_mac_table())

if __name__ == '__main__':
    asyncio.run(main())
