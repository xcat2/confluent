import asyncio
import code
import os
import socket
import sys
import confluent.util as util

#this will ultimately fill the role of the 'backdoor' of eventlet

# since we have to asyncio up the input and output, we use InteractiveInterpreter and handle the
# input ourselves, since code is not asyncio friendly in and of itself
#code.InteractiveConsole().interact()



async def interact(cloop, cnn):
    prompt = b'>>> '
    somecode = ''
    itr = code.InteractiveInterpreter()
    confile = cnn.makefile('rw')
    while True:
        await cloop.sock_sendall(cnn, prompt)
        prompt = b'... '
        newinput = b''
        while b'\n' not in newinput:
            rcv = await cloop.sock_recv(cnn, 4)
            if not rcv:
                return
            newinput += rcv
        somecode += newinput.decode()
        if newinput.startswith(b' '):
            prompt = b'... '
            continue
        try:
            compcode = code.compile_command(somecode)
        except SyntaxError as e:
            await cloop.sock_sendall(cnn, repr(e).encode('utf8'))
            await cloop.sock_sendall(cnn, b'\n')
            compcode = None
            somecode = ''
            prompt = b'>>> '
        if compcode:
            saved = sys.stdin, sys.stderr, sys.stdout
            try:
                cnn.settimeout(10)
                confile = cnn.makefile('rw')
                sys.stderr = sys.stdout = confile
                itr.runcode(compcode)
                confile.flush()
            finally:
                sys.stdin, sys.stderr, sys.stdout = saved
                cnn.settimeout(0)
            somecode = ''
            prompt = b'>>> '


async def srv_debug(sock):
    cloop = asyncio.get_event_loop()
    while True:
        print("waiting")
        cnn, addr = await cloop.sock_accept(sock)
        util.spawn(interact(cloop, cnn))
        print("next time")


def start_dbgif():
    unixsocket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    unixsocket.settimeout(0)
    try:
        os.remove("/var/run/confluent/dbg.sock")
    except OSError:  # if file does not exist, no big deal
        pass
    if not os.path.isdir("/var/run/confluent"):
        os.makedirs('/var/run/confluent', 0o755)
    oumask = os.umask(0o077)
    unixsocket.bind("/var/run/confluent/dbg.sock")
    unixsocket.listen(12)
    os.chmod("/var/run/confluent/dbg.sock",
             0o600)
    os.umask(oumask)
    util.spawn(srv_debug(unixsocket))
