import confluent.util as util
import eventlet
webclient = eventlet.import_patched('pyghmi.util.webclient')



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
        self.login()

    def login(self):
        # Just a quick query to validate that credentials are correct and device is reachable and TLS works out however it is supposed to
        self._get_state('/system/information')

        
        

    def _rpc_call(self, method, params=None):
        """Make a JSON-RPC call to SR-Linux"""
        payload = {
            'jsonrpc': '2.0',
            'id': self.rpc_id,
            'method': method,
        }
        if params:
            payload['params'] = params
        
        self.rpc_id += 1
        
        rsp = self.wc.grab_json_response_with_status('/jsonrpc', payload)
        if rsp[1] != 200:
            raise Exception(f"Failed RPC call: {method}, status: {rsp[1]}")
        
        result = rsp[0]
        if 'error' in result:
            raise Exception(f"RPC error: {result['error']}")
        
        return result.get('result', {})

    def _get_state(self, path, datastore='state'):
        """Get state data from SR-Linux using JSON-RPC get method"""
        params = {
            'commands': [
                {
                    'path': path,
                    'datastore': datastore
                }
            ]
        }
        result = self._rpc_call('get', params)
        return result

    def get_firmware(self):
        """Get firmware/software version information"""
        firmdata = {}
        result = self._get_state('/system/information')
        for item in result:
            if 'version' in item:
                firmdata['SR-Linux'] = {'version': item['version']}
            if 'build-date' in item:
                if 'SR-Linux' in firmdata:
                        firmdata['SR-Linux']['date'] = item['build-date']
        return firmdata

    def get_sensors(self):
        """Get sensor readings from the device"""
        sensedata = []
        result = self._get_state('/platform/control/temperature')
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

        result = self._get_state('/platform/fan-tray')
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

        result = self._get_state('/platform/power-supply')
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



    def get_health(self):
        healthdata = {'health': 'ok', 'sensors': []}
        sensors = self.get_sensors()
        
        for sensor in sensors:
            currhealth = sensor.get('health', 'ok')
            if currhealth != 'ok':
                healthdata['sensors'].append(sensor)
                if sensor['health'] == 'critical':
                    healthdata['health'] = 'critical'
                elif sensor['health'] == 'warning' and healthdata['health'] != 'critical':
                    healthdata['health'] = 'warning'
        
        return healthdata

    def get_inventory(self):
        invdata = []        
        results = self._get_state('/platform/chassis')
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

    def get_mac_table(self):
        macdict = {}
        response = self._get_state('/network-instance')
        for datum in response:
            for niname in datum:
                for nin in datum[niname]:
                    if nin.get('type', '').endswith('mac-vrf'):
                        mactable = nin.get('bridge-table', {}).get('mac-table', {})
                        #TODO: process mac table

        return macdict

    def get_lldp(self):
        lldpbyport = {}
        
        response = self._get_state('/system/lldp/interface')
        for datum in response:
            for intfname in datum:
                #TODO: actually process LLDP data
        return lldpbyport


if __name__ == '__main__':
    import sys
    import os
    from pprint import pprint
    myuser = os.environ.get('SWITCHUSER')
    mypass = os.environ.get('SWITCHPASS')
    if not myuser or not mypass:
        print("Set SWITCHUSER and SWITCHPASS environment variables")
        sys.exit(1)
    
    srl = SRLinuxClient(sys.argv[1], myuser, mypass, None)
    pprint(srl.get_firmware())
    pprint(srl.get_inventory())
    pprint(srl.get_sensors())
    pprint(srl.get_health())
    pprint(srl.get_lldp())
    pprint(srl.get_mac_table())
