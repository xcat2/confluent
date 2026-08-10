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

""" A simple little script to exemplify/test ipmi.console module """

import asyncio
import errno
import fcntl
import os
import sys
import termios
import tty


from aiohmi.ipmi import console


async def _feed_input(sol, inqueue):
    """Sends what the reader below collected, one chunk at a time"""

    while True:
        await sol.send_data(await inqueue.get())


def _got_input(inqueue):
    """Called by the event loop whenever stdin has something to read"""

    try:
        data = sys.stdin.read()
    except (IOError, OSError) as e:
        if e.errno == errno.EAGAIN:
            return
        raise
    if not data:
        # End of input. The reader is level triggered, so leaving it in place
        # would have the loop call this again and again for the same EOF.
        asyncio.get_running_loop().remove_reader(sys.stdin)
        return
    inqueue.put_nowait(data)


async def _print(data):
    bailout = False
    if not isinstance(data, str):
        bailout = True
        data = repr(data)
    sys.stdout.write(data)
    sys.stdout.flush()
    if bailout:
        raise Exception(data)


async def main():
    tcattr = termios.tcgetattr(sys.stdin)
    newtcattr = tcattr
    # TODO(jbjohnso): add our exit handler
    newtcattr[-1][termios.VINTR] = 0
    newtcattr[-1][termios.VSUSP] = 0
    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, newtcattr)

    tty.setraw(sys.stdin.fileno())
    currfl = fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL)
    fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, currfl | os.O_NONBLOCK)

    try:
        if sys.argv[3] is None:
            passwd = os.environ['IPMIPASSWORD']
        else:
            passwd_file = sys.argv[3]
            with open(passwd_file, "r") as f:
                passwd = f.read()

        sol = console.Console(bmc=sys.argv[1], userid=sys.argv[2],
                              password=passwd, iohandler=_print, force=True)
        await sol.connect()
        inqueue = asyncio.Queue()
        loop = asyncio.get_running_loop()
        loop.add_reader(sys.stdin, _got_input, inqueue)
        try:
            # gather rather than a detached task: a send that fails has to
            # reach the caller instead of being collected in silence.
            await asyncio.gather(sol.main_loop(), _feed_input(sol, inqueue))
        finally:
            loop.remove_reader(sys.stdin)

    except Exception:
        currfl = fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL)
        fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, currfl ^ os.O_NONBLOCK)
        termios.tcsetattr(sys.stdin, termios.TCSANOW, tcattr)
        return 0


if __name__ == '__main__':
    sys.exit(asyncio.run(main()))
