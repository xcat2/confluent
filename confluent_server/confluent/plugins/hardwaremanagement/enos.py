
# Copyright 2019 Lenovo
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


#Noncritical:
#  - One or more temperature sensors is in the warning range;
#Critical:
#  - One or more temperature sensors is in the failure range;
#  - One or more fans are running < 100 RPM;
#  - One power supply is off.

import re
import eventlet
import eventlet.queue as queue
import confluent.exceptions as exc
webclient = eventlet.import_patched("pyghmi.util.webclient")
import confluent.messages as msg
import confluent.util as util
import confluent.plugins.shell.ssh as ssh


class SwitchSensor(object):
    def __init__(self, name, states=None, units=None, value=None, health=None):
        self.name = name
        self.value = value
        self.states = states
        self.health = health
        self.units = units


def _run_method(method, workers, results, configmanager, nodes, element):
        creds = configmanager.get_node_attributes(
                nodes, ["switchuser", "switchpass", "secret.hardwaremanagementpassword",
                        "secret.hardwaremanagementuser"], decrypt=True)
        for node in nodes:
            workers.add(eventlet.spawn(method, configmanager, creds,
                                       node, results, element))


def enos_login(node, configmanager, creds):
    try:
        ukey = "switchuser"
        upass = "switchpass"
        if ukey not in creds and "secret.hardwaremanagementuser" in creds[node]:
            ukey = "secret.hardwaremanagementuser"
            upass = "secret.hardwaremanagementpassword"

        if ukey not in creds[node]:
            raise exc.TargetEndpointBadCredentials("Unable to authenticate - switchuser or secret.hardwaremanagementuser not set")
        user = creds[node][ukey]["value"]
        if upass not in creds[node]:
            passwd = None
        else:
            passwd = creds[node][upass]["value"]
        nssh = ssh.SshConn(node=node, config=configmanager, username=user, password=passwd)
        nssh.do_logon()
        return nssh
    except Exception as e:
        raise exc.TargetEndpointBadCredentials(f"Unable to authenticate {e}")


def enos_version(ssh):
    sshStdout, sshStderr = ssh.exec_command(cmd="show", cmdargs=["version"])
    return sshStdout


def update(nodes, element, configmanager, inputdata):
    for node in nodes:
        yield msg.ConfluentNodeError(node, "Not Implemented")


def delete(nodes, element, configmanager, inputdata):
    for node in nodes:
        yield msg.ConfluentNodeError(node, "Not Implemented")


def create(nodes, element, configmanager, inputdata):
    for node in nodes:
        yield msg.ConfluentNodeError(node, "Not Implemented")


def retrieve(nodes, element, configmanager, inputdata):
    results = queue.LightQueue()
    workers = set([])
    if element == ["power", "state"]:
        for node in nodes:
            yield msg.PowerState(node=node, state="on")
        return
    elif element == ["health", "hardware"]:
        _run_method(retrieve_health, workers, results, configmanager, nodes, element)
    elif element[:3] == ["inventory", "hardware", "all"]:
        _run_method(retrieve_inventory, workers, results, configmanager, nodes, element)
    elif element[:3] == ["inventory", "firmware", "all"]:
        _run_method(retrieve_firmware, workers, results, configmanager, nodes, element)
    elif element[:3] == ["sensors", "hardware", "all"]:
        _run_method(retrieve_sensors, workers, results, configmanager, nodes, element)
    else:
        for node in nodes:
            yield msg.ConfluentNodeError(node, f"Not Implemented: {element}")
        return
    currtimeout = 10
    while workers:
        try:
            datum = results.get(10)
            while datum:
                if datum:
                    yield datum
                datum = results.get_nowait()
        except queue.Empty:
            pass
        eventlet.sleep(0.001)
        for t in list(workers):
            if t.dead:
                workers.discard(t)
    try:
        while True:
            datum = results.get_nowait()
            if datum:
                yield datum
    except queue.Empty:
        pass


def retrieve_inventory(configmanager, creds, node, results, element):
    if len(element) == 3:
        results.put(msg.ChildCollection("all"))
        results.put(msg.ChildCollection("system"))
        return

    switch = gather_data(configmanager, creds, node)
    invinfo = switch["inventory"]

    for fan, data in switch["fans"].items():
        invinfo["inventory"][0]["information"][f"Fan #{fan}"] = data["state"]

    for psu, data in switch["psus"].items():
        invinfo["inventory"][0]["information"][f"PSU #{psu}"] = data["state"]

    results.put(msg.KeyValueData(invinfo, node))


def gather_data(configmanager, creds, node):
    nssh = enos_login(node=node, configmanager=configmanager, creds=creds)
    switch_lines = enos_version(ssh=nssh)
    switch_data = {}
    sysinfo = {"Product name": {"regex": ".*RackSwitch (\w+)"},
               "Serial Number": {"regex": "ESN\s*\w*\s*: ([\w-]+)"},
               "Board Serial Number": {"regex": "Switch Serial No: (\w+)"},
               "Model": {"regex": "MTM\s*\w*\s*: ([\w-]+)"},
               "FRU Number": {"regex": "Hardware Part\s*\w*\s*: (\w+)"},
               "Airflow": {"regex": "System Fan Airflow\s*\w*\s*: ([\w-]+)"},
              }

    invinfo = {
        "inventory": [{
            "name": "System",
            "present": True,
            "information": {
                "Manufacturer": "Lenovo",
            }
        }]
    }

    switch_data["sensors"] = []

    switch_data["fans"] = gather_fans(switch_lines)
    for fan, data in switch_data["fans"].items():
        if "rpm" in data:
            health = "ok"
            if int(data["rpm"]) < 100:
                health = "critical"
            switch_data["sensors"].append(SwitchSensor(name=f"Fan {fan}", value=data['rpm'],
                                          units="RPM", health=health))

    switch_data["psus"] = gather_psus(switch_lines)

    # Hunt for the temp limits
    phylimit = {"warn": None, "shut": None}
    templimit = {"warn": None, "shut": None}
    for line in switch_lines:
        match = re.match(r"([\w\s]+)Warning[\w\s]+\s(\d+)[\sA-Za-z\/]+\s(\d+)[\s\w\/]+\s(\d*)", line)
        if match:
            if "System" in match.group(1):
                templimit["warn"] = int(match.group(2))
                templimit["shut"] = int(match.group(3))
            elif "PHYs" in match.group(1):
                phylimit["warn"] = int(match.group(2))
                phylimit["shut"] = int(match.group(3))
    if not phylimit["warn"]:
        phylimit = templimit

    for line in switch_lines:
        # match the inventory data
        for key in sysinfo.keys():
            match = re.match(re.compile(sysinfo[key]["regex"]), line)
            if match:
                invinfo["inventory"][0]["information"][key] = match.group(1).strip()

        # match temp sensors logging where failed
        match = re.match(r"Temperature\s+([\d\s\w]+)\s*:\s*(\d+)+\s+([CF])+", line)
        if match:
            health = "ok"
            temp = int(match.group(2))
            name = f"{match.group(1).strip()} Temp"
            if "Phy" in name:
                if temp > phylimit["warn"]:
                    health = "warning"
                if temp > phylimit["shut"]:
                    health = "critical"
            else:
                if temp > templimit["warn"]:
                    health = "warning"
                if temp > templimit["shut"]:
                    health = "critical"
            switch_data["sensors"].append(SwitchSensor(name=name,
                                          value=temp, units=f"°{match.group(3)}", health=health))
        match = re.match(r"\s*(\w+) Faults\s*:\s+(.+)", line)
        if match and match.group(2) not in ["()", "None"]:
            switch_data["sensors"].append(SwitchSensor(name=f"{match.group(1)} Fault",
                                          value=match.group(2).strip(), units="", health="critical"))

    switch_data["inventory"] = invinfo

    sysfw = {"Software Version": "Unknown", "Boot kernel": "Unknown"}
    for line in switch_lines:
        for key in sysfw.keys():
            regex = f"{key}\s*\w*\s* ([0-9.]+)"
            match = re.match(re.compile(regex), line)
            if match:
                sysfw[key] = match.group(1)
    switch_data["firmware"] = sysfw

    return switch_data


def gather_psus(data):
    psus = {}
    for line in data:
        # some switches are:
        # Power Supply 1: Back-To-Front
        # others are:
        # Internal  Power Supply: On
        if "Power Supply" in line:
            match = re.match(re.compile(f"Power Supply (\d)+.*"), line)
            if match:
                psu = match.group(1)
                if psu not in psus:
                    psus[psu] = {}
                m = re.match(r".+\s+(\w+\-\w+\-\w+)\s*\[*.*$", line)
                if m:
                    psus[psu]["airflow"] = m.group(1)
                    psus[psu]["state"] = "Present"
                else:
                    psus[psu]["state"] = "Not installed"
            else:
                for psu in range(1, 10):
                    if "Power Supply" in line and psu not in psus:
                        if psu not in psus:
                            psus[psu] = {}
                        if "Not Installed" in line:
                            psus[psu]["state"] = "Not installed"
                            break
                        else:
                            psus[psu]["state"] = "Present"
                            break
    return psus


def gather_fans(data):
    fans = {}
    for line in data:
        # look for presence of fans
        if "Fan" in line:
            match = re.match(re.compile(f"Fan (\d)+.*"), line)
            if match:
                fan = match.group(1)
                if match:
                    if fan not in fans:
                        fans[fan] = {}
                    if "rpm" in line or "RPM" in line:
                        if "Module" in line:
                            m = re.search(r"Module\s+(\d)+:", line)
                            if m:
                                fans[fan]["Module"] = m.group(1)
                        fans[fan]["state"] = "Present"
                        m = re.search(r"(\d+)\s*:\s+(RPM=)*(\d+)(rpm)*", line)
                        if m:
                            fans[fan]["rpm"] = m.group(3)

                        m = re.search(r"\s+(PWM=)*(\d+)(%|pwm)+", line)
                        if m:
                            fans[fan]["pwm"] = m.group(2)

                        m = re.search(r"(.+)\s+(\w+\-\w+\-\w+)$", line)
                        if m:
                            fans[fan]["airflow"] = m.group(1)
                    else:
                        fans[fan]["state"] = "Not installed"
    return fans


def retrieve_firmware(configmanager, creds, node, results, element):
    if len(element) == 3:
        results.put(msg.ChildCollection("all"))
        return
    sysinfo = gather_data(configmanager, creds, node)["firmware"]
    items = [{
        "Software": {"version": sysinfo["Software Version"]},
        },
        {
        "Boot kernel": {"version": sysinfo["Boot kernel"]},
        }]
    results.put(msg.Firmware(items, node))


def retrieve_health(configmanager, creds, node, results, element):
    switch = gather_data(configmanager, creds, node)
    badreadings = []
    summary = "ok"
    sensors = gather_data(configmanager, creds, node)["sensors"]

    for sensor in sensors:
        if sensor.health not in ["ok"]:
            if sensor.health in ["critical"]:
                summary = "critical"
            elif summary in ["ok"] and sensor.health in ["warning"]:
                summary = "warning"
            badreadings.append(sensor)
    results.put(msg.HealthSummary(summary, name=node))
    results.put(msg.SensorReadings(badreadings, name=node))


def retrieve_sensors(configmanager, creds, node, results, element):
    sensors = gather_data(configmanager, creds, node)["sensors"]
    results.put(msg.SensorReadings(sensors, node))
