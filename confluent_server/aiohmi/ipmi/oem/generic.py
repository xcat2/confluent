# Copyright 2015 Lenovo Corporation
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

import aiohmi.exceptions as exc
import aiohmi.ipmi.private.constants as event_const
import aiohmi.ipmi.sdr as ipmisdr
import struct

class OEMHandler(object):
    """Handler class for OEM capabilities.

    Any vendor wishing to implement OEM extensions should look at this
    base class for an appropriate interface.  If one does not exist, this
    base class should be extended.  At initialization an OEM is given
    a dictionary with product_id, device_id, manufacturer_id, and
    device_revision as keys in a dictionary, along with an ipmi Command object
    """

    @classmethod
    async def create(cls, oemid, ipmicmd):
        self = cls()
        return self

    async def get_video_launchdata(self):
        return {}

    async def get_description(self):
        """Get a description of descriptive attributes of a node.

        Height describes, in U how tall the system is, and slot is 0 if
        not a blade type server, and slot if it is.

        :return: dictionary with 'height' and 'slot' members
        """
        return {}
    
    async def get_screenshot(self, outfile):
        return {}    

    async def get_system_power_watts(self, ipmicmd):
        # Use DCMI getpower reading command
        rsp = await ipmicmd.raw_command(netfn=0x2c, command=2, data=(0xdc, 1, 0, 0))
        wattage = struct.unpack('<H', rsp['data'][1:3])[0]
        return wattage   

    async def get_ikvm_methods(self):
        return []

    async def get_ikvm_launchdata(self):
        # no standard ikvm behavior, must be oem defined
        return {}

    async def get_average_processor_temperature(self, ipmicmd):
        # DCMI suggests preferrence for 0x37 ('Air inlet')
        # If not that, then 0x40 ('Air inlet')
        # in practice, some implementations use 0x27 ('External environment')
        if not hasattr(self, '_processor_names'):
            self._processor_names = []
        if not self._processor_names:
            sdr = await ipmicmd.init_sdr()
            for sensename in sdr.sensors:
                sensor = sdr.sensors[sensename]
                if sensor.reading_type != 1:
                    continue
                if not sensor.baseunit:
                    continue
                if sensor.sensor_type != 'Temperature':
                    continue
                if sensor.entity == 'Processor':
                    self._processor_names.append(sensor.sensor_name)
        readingvalues = []
        for procsensor in self._processor_names:
            try:
                reading = await ipmicmd.get_sensor_reading(procsensor)
            except exc.IpmiException:
                continue
            if reading.value is not None:
                readingvalues.append(float(reading.value))
        tmplreading = ipmisdr.SensorReading({'name': 'Average Processor Temperature', 'type': 'Temperature'}, '°C')
        if readingvalues:
            tmplreading.value = sum(readingvalues) / len(readingvalues)
        else:
            tmplreading.value = None
            tmplreading.unavailable = 1
        return tmplreading


    async def get_inlet_temperature(self, ipmicmd):
        # DCMI suggests preferrence for 0x37 ('Air inlet')
        # If not that, then 0x40 ('Air inlet')
        # in practice, some implementations use 0x27 ('External environment')
        if not hasattr(self, '_inlet_name'):
            self._inlet_name = None
        if self._inlet_name:
            return await ipmicmd.get_sensor_reading(self._inlet_name)
        sdr = await ipmicmd.init_sdr()
        extenv = []
        airinlets = []
        for sensename in sdr.sensors:
            sensor = sdr.sensors[sensename]
            if sensor.reading_type != 1:
                continue
            if not sensor.baseunit:
                continue
            if sensor.sensor_type != 'Temperature':
                continue
            if sensor.entity == 'External environment':
                if 'exhaust' in sensor.sensor_name.lower():
                    continue
                extenv.append(sensor.sensor_name)
            if sensor.entity == 'Air inlet':
                airinlets.append(sensor.sensor_name)
        if airinlets:
            if len(airinlets) > 1:
                raise Exception('TODO: how to deal with multiple inlets')
            self._inlet_name = airinlets[0]
        elif extenv:
            if len(extenv) > 1:
                raise Exception('TODO: how to deal with multiple external environments')
            self._inlet_name = extenv[0]
        if not self._inlet_name:
            raise exc.UnsupportedFunctionality(
                'Unable to detect inlet sensor name for this platform')
        return await ipmicmd.get_sensor_reading(self._inlet_name)

    async def process_event(self, event, ipmicmd, seldata):
        """Modify an event according with OEM understanding.

        Given an event, allow an OEM module to augment it.  For example,
        event data fields can have OEM bytes.  Other times an OEM may wish
        to apply some transform to some field to suit their conventions.
        """
        event['oem_handler'] = None
        evdata = event['event_data_bytes']
        if evdata[0] & 0b11000000 == 0b10000000:
            event['oem_byte2'] = evdata[1]
        if evdata[0] & 0b110000 == 0b100000:
            event['oem_byte3'] = evdata[2]

    async def clear_system_configuration(self):
        raise exc.UnsupportedFunctionality(
            'Clearing system configuration not implemented for this platform')

    async def clear_bmc_configuration(self):
        raise exc.UnsupportedFunctionality(
            'Clearing BMC configuration not implemented for this platform')

    async def get_oem_inventory_descriptions(self):
        """Get descriptions of available additional inventory items

        OEM implementation may provide additional records not indicated
        by FRU locator SDR records.  An implementation is expected to
        implement this function to list component names that would map to
        OEM behavior beyond the specification.  It should return an iterable
        of names
        """
        if False:
            yield None

    async def get_sensor_reading(self, sensorname):
        """Get an OEM sensor

        If software wants to model some OEM behavior as a 'sensor' without
        doing SDR, this hook provides that ability.  It should mimic
        the behavior of 'get_sensor_reading' in command.py.
        """
        raise Exception('Sensor not found: ' + sensorname)

    async def get_sensor_descriptions(self):
        """Get list of OEM sensor names and types

        Iterate over dicts describing a label and type for OEM 'sensors'.  This
        should mimic the behavior of the get_sensor_descriptions function
        in command.py.
        """
        if False:
            yield None

    async def get_diagnostic_data(self, savefile, progress=None):
        """Download diagnostic data about target to a file

        This should be a payload that the vendor's support team can use
        to do diagnostics.
        :param savefile: File object or filename to save to
        :param progress: Callback to be informed about progress
        :return:
        """
        raise exc.UnsupportedFunctionality(
            'Do not know how to get diagnostic data for this platform')

    async def get_sensor_data(self):
        """Get OEM sensor data

        Iterate through all OEM 'sensors' and return data as if they were
        normal sensors.  This should mimic the behavior of the get_sensor_data
        function in command.py.
        """
        if False:
            yield None

    async def get_oem_inventory(self):
        """Get tuples of component names and inventory data.

        This returns an iterable of tuples.  The first member of each tuple
        is a string description of the inventory item.  The second member
        is a dict of inventory information about the component.
        """
        async for desc in self.get_oem_inventory_descriptions():
            yield (desc, await self.get_inventory_of_component(desc))

    async def get_inventory_of_component(self, component):
        """Get inventory detail of an OEM defined component

        Given a string that may be an OEM component, return the detail of that
        component.  If the component does not exist, returns None
        """
        return None

    async def get_leds(self):
        """Get tuples of LED categories.

        Each category contains a category name and a dicionary of LED names
        with their status as values.
        """
        if False:
            yield None

    async def get_ntp_enabled(self):
        """Get whether ntp is enabled or not

        :returns: True if enabled, False if disabled, None if unsupported
        """
        return None

    async def set_ntp_enabled(self, enabled):
        """Set whether NTP should be enabled

        :returns: True on success
        """
        return None

    async def get_ntp_servers(self):
        """Get current set of configured NTP servers

        :returns iterable of configured NTP servers:
        """
        return ()

    async def set_ntp_server(self, server, index=0):
        """Set an ntp server

        :param server:  Destination address of server to reach
        :param index: Index of server to configure, primary assumed if not
        specified
        :returns: True if success
        """
        return None

    async def process_fru(self, fru, name=None):
        """Modify a fru entry with OEM understanding.

        Given a fru, clarify 'extra' fields according to OEM rules and
        return the transformed data structure.  If OEM processes, it is
        expected that it sets 'oem_parser' to the name of the module.  For
        clients passing through data, it is suggested to pass through
        board/product/chassis_extra_data arrays if 'oem_parser' is None,
        and mask those fields if not None.  It is expected that OEMs leave
        the fields intact so that if client code hard codes around the
        ordered lists that their expectations are not broken by an update.
        """
        # In the generic case, just pass through
        if fru is None:
            return fru
        fru['oem_parser'] = None
        return fru

    async def get_oem_firmware(self, bmcver, components, category):
        """Get Firmware information."""

        # Here the bmc version is passed into the OEM handler, to allow
        # the handler to enrich the data. For the generic case, just
        # provide the generic BMC version, which is all that is possible
        # Additionally, components may be provided for an advisory guide
        # on interesting firmware.  The OEM library is permitted to return
        # more than requested, and it is the responsibility of the calling
        # code to know whether it cares or not.  The main purpose of the
        # components argument is to indicate when certain performance
        # optimizations can be performed.
        yield 'BMC Version', {'version': bmcver}

    async def get_oem_capping_enabled(self):
        """Get PSU based power capping status

        :return: True if enabled and False if disabled
        """
        return ()

    async def set_oem_capping_enabled(self, enable):
        """Set PSU based power capping

        :param enable: True for enable and False for disable
        """
        return ()

    async def get_oem_remote_kvm_available(self):
        """Get remote KVM availability"""
        return False

    async def get_oem_domain_name(self):
        """Get Domain name"""
        return ()

    async def set_oem_domain_name(self, name):
        """Set Domain name

        :param name: domain name to be set
        """
        return ()

    async def clear_storage_arrays(self):
        raise exc.UnsupportedFunctionality(
            'Remote storage configuration not supported on this platform')

    async def remove_storage_configuration(self, cfgspec):
        raise exc.UnsupportedFunctionality(
            'Remote storage configuration not supported on this platform')

    async def apply_storage_configuration(self, cfgspec):
        raise exc.UnsupportedFunctionality(
            'Remote storage configuration not supported on this platform')

    async def check_storage_configuration(self, cfgspec):
        raise exc.UnsupportedFunctionality(
            'Remote storage configuration not supported on this platform')

    async def get_storage_configuration(self):
        raise exc.UnsupportedFunctionality(
            'Remote storage configuration not supported on this platform')

    async def get_update_status(self):
        raise exc.UnsupportedFunctionality(
            'Firmware update not supported on this platform')

    async def update_firmware(self, filename, data=None, progress=None, bank=None):
        raise exc.UnsupportedFunctionality(
            'Firmware update not supported on this platform')

    async def reseat_bay(self, bay):
        raise exc.UnsupportedFunctionality(
            'Reseat not supported on this platform')

    async def get_graphical_console(self):
        """Get graphical console launcher"""
        return ()

    async def add_extra_net_configuration(self, netdata, channel=None):
        """Add additional network configuration data

        Given a standard netdata struct, add details as relevant from
        OEM commands, modifying the passed dictionary
        :param netdata: Dictionary to store additional network data
        """
        return

    async def get_oem_identifier(self):
        """Get host name

        """
        return None

    async def set_oem_identifier(self, name):
        """Set host name

        :param name: host name to be set
        """
        return False

    async def detach_remote_media(self):
        raise exc.UnsupportedFunctionality()

    async def attach_remote_media(self, imagename, username, password):
        raise exc.UnsupportedFunctionality()

    async def upload_media(self, filename, progress, data):
        raise exc.UnsupportedFunctionality(
            'Remote media upload not supported on this system')

    async def list_media(self):
        if False:
            yield None
        raise exc.UnsupportedFunctionality()

    async def set_identify(self, on, duration, blink):
        """Provide an OEM override for set_identify

        Some systems may require an override for set identify.

        """
        raise exc.UnsupportedFunctionality()

    async def get_health(self, summary):
        """Provide an alternative or augmented health assessment

        An OEM handler can preprocess the summary and extend it with OEM
        specific data, and then return to let generic processing occur.
        It can also raise the aiohmi exception BypassGenericBehavior to
        suppress the standards based routine, for enhanced performance.

        :param summary: The health summary as prepared by the generic function
        :return: Nothing, modifies the summary object
        """
        return []

    async def set_hostname(self, hostname):
        """OEM specific hook to specify name information"""
        raise exc.UnsupportedFunctionality()

    async def get_hostname(self):
        """OEM specific hook to specify name information"""
        raise exc.UnsupportedFunctionality()

    async def set_user_access(self, uid, channel, callback, link_auth, ipmi_msg,
                        privilege_level):
        if privilege_level.startswith('custom.'):
            raise exc.UnsupportedFunctionality()
        return  # Nothing to do

    async def set_alert_ipv6_destination(self, ip, destination, channel):
        """Set an IPv6 alert destination

        If and only if an implementation does not support standard
        IPv6 but has an OEM implementation, override this to process
        the data.

        :param ip: IPv6 address to set
        :param destination: Destination number
        :param channel: Channel number to apply

        :returns True if standard parameter set should be suppressed
        """
        return False

    async def get_extended_bmc_configuration(self):
        """Get extended bmc configuration

        In the case of potentially redundant/slow
        attributes, retrieve unpopular options that may be
        redundant or confusing and slow.
        """
        return {}

    async def get_bmc_configuration(self):
        """Get additional BMC parameters

        This allows a bmc to return arbitrary key-value pairs.
        """
        return {}

    async def set_bmc_configuration(self, changeset):
        raise exc.UnsupportedFunctionality(
            'Platform does not support setting bmc attributes')

    async def get_system_configuration(self, hideadvanced):
        """Retrieve system configuration

        This returns a dictionary of settings names to dictionaries including
        'current', 'default' and 'possible' values as well as 'help'

        :param hideadvanced: Whether to hide 'advanced' settings that most
                             users should not need.  Defaults to True.
        """
        return {}

    async def set_system_configuration(self, changeset):
        """Apply a changeset to system configuration

        Takes a key value pair and applies it against the system configuration
        """
        raise exc.UnsupportedFunctionality()

    async def get_licenses(self):
        raise exc.UnsupportedFunctionality()
        yield None

    async def delete_license(self, name):
        raise exc.UnsupportedFunctionality()

    async def save_licenses(self, directory):
        raise exc.UnsupportedFunctionality()
        yield None

    async def apply_license(self, filename, progress=None, data=None):
        raise exc.UnsupportedFunctionality()
        yield None

    async def get_user_expiration(self, uid):
        return None
    
    async def get_user_privilege_level(self, uid):
        return None

    async def set_oem_extended_privilleges(self, uid):
        """Set user extended privillege as 'KVM & VMedia Allowed'

        |KVM & VMedia Not Allowed	0x00 0x00 0x00 0x00
        |KVM Only Allowed	0x01 0x00 0x00 0x00
        |VMedia Only Allowed	0x02  0x00 0x00 0x00
        |KVM & VMedia Allowed	0x03 0x00 0x00 0x00

        :param uid: User ID.
        """
        return False

    async def process_zero_fru(self, zerofru):
        return await self.process_fru(zerofru)

    async def is_valid(self, name):
        return name is not None

    async def process_password(self, password, data):
        return data

    async def set_server_capping(self, value):
        """Set power capping for server

        :param value: power capping value to set.
        """
        pass

    async def get_server_capping(self):
        """Get power capping for server

        :return: power capping value.
        """
        return None

    async def get_oem_event_const(self):
        return event_const
