# Copyright 2013 IBM Corporation
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

"""This is an example of using the library in a synchronous fashion. For now,
it isn't conceived as a general utility to actually use, just help developers
understand how the ipmi_command class workes.
"""

import asyncio
import os
import sys

from aiohmi.ipmi import command


async def docommand(args, ipmicmd):
    command = args[0]
    args = args[1:]
    print("Logged into %s" % ipmicmd.bmc)
    if command == 'power':
        if args:
            print(await ipmicmd.set_power(args[0], wait=True))
        else:
            value = await ipmicmd.get_power()
            print("%s: %s" % (ipmicmd.bmc, value['powerstate']))
    elif command == 'bootdev':
        if args:
            print(await ipmicmd.set_bootdev(args[0]))
        else:
            print(await ipmicmd.get_bootdev())
    elif command == 'sensors':
        async for reading in ipmicmd.get_sensor_data():
            print(reading)
    elif command == 'health':
        print(await ipmicmd.get_health())
    elif command == 'inventory':
        async for item in ipmicmd.get_inventory():
            print(item)
    elif command == 'leds':
        async for led in ipmicmd.get_leds():
            print(led)
    elif command == 'graphical':
        print(await ipmicmd.get_graphical_console())
    elif command == 'net':
        print(await ipmicmd.get_net_configuration())
    elif command == 'raw':
        print(await ipmicmd.raw_command(
              netfn=int(args[0]),
              command=int(args[1]),
              data=[int(x, 16) for x in args[2:]]))


async def main():
    if (len(sys.argv) < 3) or 'IPMIPASSWORD' not in os.environ:
        print("Usage:")
        print(" IPMIPASSWORD=password %s bmc username <cmd> <optarg>" %
              sys.argv[0])
        return 1

    password = os.environ['IPMIPASSWORD']
    os.environ['IPMIPASSWORD'] = ""
    bmcs = sys.argv[1].split(',')
    userid = sys.argv[2]

    for bmc in bmcs:
        ipmicmd = await command.Command.create(
            bmc=bmc, userid=userid, password=password)
        await docommand(sys.argv[3:], ipmicmd)


if __name__ == '__main__':
    sys.exit(asyncio.run(main()))
