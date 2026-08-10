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

"""This is a simple, but working proof of concept of using aiohmi.ipmi.bmc to
control a VM
"""

import argparse
import asyncio
import sys
import threading

import libvirt

import aiohmi.ipmi.bmc as bmc


def lifecycle_callback(connection, domain, event, detail, console):
    console.state = console.domain.state(0)


def error_handler(unused, error):
    if (error[0] == libvirt.VIR_ERR_RPC
            and error[1] == libvirt.VIR_FROM_STREAMS):
        return


def stream_callback(stream, events, console):
    try:
        data = console.stream.recv(1024)
    except Exception:
        return
    if console.sol and console.asyncloop:
        # libvirt calls this from its own event thread, and asyncio objects
        # are not thread safe, so hand the send to the loop that owns them.
        asyncio.run_coroutine_threadsafe(console.sol.send_data(data),
                                         console.asyncloop)


class LibvirtBmc(bmc.Bmc):
    """A class to provide an IPMI interface to the VirtualBox APIs."""

    def __init__(self, authdata, hypervisor, domain, port):
        super(LibvirtBmc, self).__init__(authdata, port)
        # Rely on libvirt to throw on bad data
        self.conn = libvirt.open(hypervisor)
        self.name = domain
        self.domain = self.conn.lookupByName(domain)
        self.state = self.domain.state(0)
        self.stream = None
        self.asyncloop = None
        self.run_console = False
        self.conn.domainEventRegister(lifecycle_callback, self)
        self.sol_thread = None

    def cold_reset(self):
        # Reset of the BMC, not managed system, here we will exit the demo
        print('shutting down in response to BMC cold reset request')
        sys.exit(0)

    def get_power_state(self):
        if self.domain.isActive():
            return 'on'
        else:
            return 'off'

    def power_off(self):
        if not self.domain.isActive():
            return 0xd5  # Not valid in this state
        self.domain.destroy()

    def power_on(self):
        if self.domain.isActive():
            return 0xd5  # Not valid in this state
        self.domain.create()

    def power_reset(self):
        if not self.domain.isActive():
            return 0xd5  # Not valid in this state
        self.domain.reset()

    def power_shutdown(self):
        if not self.domain.isActive():
            return 0xd5  # Not valid in this state
        self.domain.shutdown()

    def is_active(self):
        return self.domain.isActive()

    def check_console(self):
        if (self.state[0] == libvirt.VIR_DOMAIN_RUNNING
                or self.state[0] == libvirt.VIR_DOMAIN_PAUSED):
            if self.stream is None:
                self.stream = self.conn.newStream(libvirt.VIR_STREAM_NONBLOCK)
                self.domain.openConsole(None, self.stream, 0)
                self.stream.eventAddCallback(libvirt.VIR_STREAM_EVENT_READABLE,
                                             stream_callback, self)
        else:
            if self.stream:
                self.stream.eventRemoveCallback()
                self.stream = None

        return self.run_console

    async def activate_payload(self, request, session):
        # captured for stream_callback, which runs on a libvirt thread
        self.asyncloop = asyncio.get_running_loop()
        wasactive = self.activated
        await super(LibvirtBmc, self).activate_payload(request, session)
        if wasactive or not self.activated:
            # the base handler refused: no io handler, or the domain is not
            # running, so activated stayed false; or a console was already up,
            # in which case activated was true before we asked and the thread
            # for it is already running. Either way there is nothing to start.
            return
        self.run_console = True
        self.sol_thread = threading.Thread(target=self.loop)
        # virEventRunDefaultImpl can wait for an event that never comes, so
        # this thread has no reliable end of its own
        self.sol_thread.daemon = True
        self.sol_thread.start()

    async def deactivate_payload(self, request, session):
        if self.activated and self.sol_thread:
            self.run_console = False
            # Joining here would run on the event loop, and the thread sits in
            # virEventRunDefaultImpl, which is documented as able to wait
            # indefinitely: clearing run_console does not wake it. So wait off
            # the loop, and not forever, rather than stall every other session
            # and never send the response below.
            await asyncio.get_running_loop().run_in_executor(
                None, self.sol_thread.join, 5)
            self.sol_thread = None
        await super(LibvirtBmc, self).deactivate_payload(request, session)

    async def iohandler(self, data):
        if self.stream:
            self.stream.send(data)

    def loop(self):
        while self.check_console():
            libvirt.virEventRunDefaultImpl()


def main():
    parser = argparse.ArgumentParser(
        prog='virshbmc',
        description='Pretend to be a BMC and proxy to virsh',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--port',
                        dest='port',
                        type=int,
                        default=623,
                        help='(UDP) port to listen on')
    parser.add_argument('--connect',
                        dest='hypervisor',
                        default='qemu:///system',
                        help='The hypervisor to connect to')
    parser.add_argument('--domain',
                        dest='domain',
                        required=True,
                        help='The name of the domain to manage')
    args = parser.parse_args()

    libvirt.virEventRegisterDefaultImpl()
    libvirt.registerErrorHandler(error_handler, None)

    mybmc = LibvirtBmc({'admin': 'password'},
                       hypervisor=args.hypervisor,
                       domain=args.domain,
                       port=args.port)
    asyncio.run(mybmc.listen())


if __name__ == '__main__':
    sys.exit(main())
