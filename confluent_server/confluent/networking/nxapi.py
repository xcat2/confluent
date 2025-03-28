
import confluent.util as util
import time
import eventlet
webclient = eventlet.import_patched('pyghmi.util.webclient')

_healthmap = {
    'normal': 'ok',
    'minor': 'warning',
    'major': 'critical',
}

def add_sensedata(component, sensedata, name=None):
    senseinfo = {}
    if 'eqptSensor' in component:
        attrs = component['eqptSensor']['attributes']
        senseinfo['name'] = attrs['descr']
        senseinfo['value'] = attrs['tempValue']
        units = attrs['unit']
        if units == 'Celsius':
            units = '°C'
        senseinfo['units'] = units
        senseinfo['health'] = _healthmap.get(attrs['operSt'], 'unknown')
        if senseinfo['health'] == 'unknown':
            print(senseinfo['health'] + ' not recognized')
            senseinfo['health'] = 'critical'
    elif 'eqptFtSlot' in component:
        attrs = component['eqptFtSlot']['attributes']
        name = '{} {}'.format(attrs['descr'], attrs['physId'])
    elif 'eqptFan' in component:
        attrs = component['eqptFan']['attributes']
        if name:
            senseinfo['name'] = '{}/{}'.format(name, attrs['id'])
        else:
            senseinfo['name'] = '{}  {}'.format(attrs['descr'], attrs['id'])
        senseinfo['value'] = attrs['speedInRpm']
        senseinfo['units'] = 'RPM'
        senseinfo['health'] = attrs['operSt']
    elif 'eqptPsu' in component:
        attrs = component['eqptPsu']['attributes']
        senseinfo['name'] = 'PSU {} Output Current'.format(attrs['id'])
        senseinfo['value'] = attrs['drawnCurr']
        senseinfo['units'] = 'A'
        sensedata.append(senseinfo)
        senseinfo = {}
        senseinfo['name'] = 'PSU {} Input Current'.format(attrs['id'])
        senseinfo['value'] = attrs['inputCurr']
        senseinfo['units'] = 'A'
        sensedata.append(senseinfo)
        senseinfo = {}
        senseinfo['name'] = 'PSU {} Output Voltage'.format(attrs['id'])
        senseinfo['value'] = attrs['volt']
        senseinfo['units'] = 'V'
        sensedata.append(senseinfo)
        senseinfo = {}
    elif 'eqptPsuSlot' in component:
        attrs = component['eqptPsuSlot']['attributes']
        senseinfo['value'] = None
        senseinfo['units'] = None
        senseinfo['name'] = 'PSU Slot {}'.format(attrs['physId'])
        senseinfo['health'] = 'ok'
        senseinfo['states'] = ['Present']
        if attrs['operSt'] == 'empty':
            senseinfo['health'] = 'critical'
            senseinfo['states'] = 'Absent'
    if senseinfo:
        sensedata.append(senseinfo)
    for key in component:
        if 'children' in component[key]:
            for child in component[key]['children']:
                add_sensedata(child, sensedata, name)


class NxApiClient:
    def __init__(self, switch, user, password, configmanager):
        self.cachedurls = {}
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
        self.login()

    def login(self):
        payload = {'aaaUser':
                       {'attributes':
                            {'name': self.user,
                             'pwd': self.password}}}
        rsp = self.wc.grab_json_response_with_status('/api/mo/aaaLogin.json', payload)
        if rsp[1] != 200:
            raise Exception("Failed authenticating")
        rsp = rsp[0]
        self.authtoken = rsp['imdata'][0]['aaaLogin']['attributes']['token']
        self.wc.cookies['Apic-Cookie'] = self.authtoken

    def get_firmware(self):
        firmdata = {}
        for imdata in self.grab_imdata('/api/mo/sys/showversion.json'):
            attrs = imdata['sysmgrShowVersion']['attributes']
            firmdata['NX-OS'] = {'version': attrs['nxosVersion'], 'date': attrs['nxosCompileTime']}
            firmdata['BIOS'] = {'version': attrs['biosVersion'], 'date': attrs['biosCompileTime']}
        return firmdata

    def get_sensors(self):
        sensedata = []
        for imdata in self.grab_imdata('/api/mo/sys/ch.json?rsp-subtree=full'):
            hwinfo = imdata['eqptCh']['children']
            for component in hwinfo:
                add_sensedata(component, sensedata)
        return sensedata

    def get_health(self):
        healthdata = {'health': 'ok', 'sensors': []}
        for sensor in self.get_sensors():
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
        for imdata in self.grab_imdata('/api/mo/sys/ch.json?rsp-subtree=full'):
            hwinfo = imdata['eqptCh']
            chattr = hwinfo['attributes']
            invinfo = {'name': 'System', 'present': True}
            invinfo['information'] = {
                    'Manufacturer': chattr['vendor'],
                    'Serial Number': chattr['ser'],
                    'Product name': chattr['descr'],
                    'Model': chattr['model'],
                    'Revision': chattr['rev'],
                }
            invdata.append(invinfo)
            for comp in hwinfo['children']:
                if 'eqptPsuSlot' in comp:
                    attrs = comp['eqptPsuSlot']['attributes']
                    name = '{} {}'.format(attrs['descr'], attrs['id'])
                    if attrs['operSt'] == 'empty':
                        invinfo = {'name': name, 'present': False}
                    else:
                        invinfo = {'name': name, 'present': True}
                        psuinfo = comp['eqptPsuSlot']['children'][0]['eqptPsu']['attributes']
                        invinfo['information'] = {
                            'Manufacturer': psuinfo['vendor'],
                            'Model': psuinfo['model']
                            }
                    invdata.append(invinfo)
        return invdata

    def grab(self, url, cache=True, retry=True):
        if cache is True:
            cache = 1
        if cache:
            if url in self.cachedurls:
                if self.cachedurls[url][1] > time.monotonic() - cache:
                    return self.cachedurls[url][0]
        rsp = self.wc.grab_json_response_with_status(url)
        if rsp[1] == 403 and retry:
            self.login()
            return self.grab(url, cache, False)
        if rsp[1] != 200:
            raise Exception("Error making request")
        self.cachedurls[url] = rsp[0], time.monotonic()
        return rsp[0]

    def grab_imdata(self, url):
        response = self.grab(url)
        for imdata in response['imdata']:
            yield imdata

    def get_mac_table(self):
        macdict = {}
        for macinfo in self.grab_imdata('/api/mo/sys/mac/table.json?rsp-subtree=full'):
            mactable = macinfo['l2MacAddressTable']['children']
            for macent in mactable:
                mace = macent['l2MacAddressEntry']['attributes']
                mace['macAddress'] = mace['macAddress'].lower()
                if mace['port'] in macdict:
                    macdict[mace['port']].append(mace['macAddress'])
                else:
                    macdict[mace['port']] = [mace['macAddress']]
        return macdict


    def get_lldp(self):
        lldpbyport = {}
        for lldpimdata in self.grab_imdata('/api/mo/sys/lldp/inst.json?rsp-subtree=full'):
            lldpdata = lldpimdata['lldpInst']['children']
            for lldpinfo in lldpdata:
                if 'lldpIf' not in lldpinfo:
                    continue
                port_id = lldpinfo['lldpIf']['attributes']['id']
                for child in lldpinfo['lldpIf'].get('children', []):
                    if 'lldpAdjEp' not in child:
                        continue
                    record = child['lldpAdjEp']['attributes']
                    lldpinfo = {
                        'verified': True, # over TLS
                        'peerdescription': record['sysDesc'],
                        'peername': record['sysName'],
                        'peerchassisid': record['chassisIdV'],
                        'peerportid': record['portIdV'],
                        'portid': port_id,
                        'port': port_id,
                    }
                    lldpbyport[port_id] = lldpinfo
        return lldpbyport


if __name__ == '__main__':
    import sys
    import os
    from pprint import pprint
    myuser = os.environ['SWITCHUSER']
    mypass = os.environ['SWITCHPASS']
    na = NxApiClient(sys.argv[1], myuser, mypass, None)
    pprint(na.get_firmware())
    pprint(na.get_lldp())
    pprint(na.get_mac_table())
    pprint(na.get_inventory())
    pprint(na.get_sensors())
