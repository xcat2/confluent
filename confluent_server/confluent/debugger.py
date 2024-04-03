import asyncio
import code
import sys

#this will ultimately fill the role of the 'backdoor' of eventlet

# since we have to asyncio up the input and output, we use InteractiveInterpreter and handle the
# input ourselves, since code is not asyncio friendly in and of itself
#code.InteractiveConsole().interact()
async def interact(sock):
    cloop = asyncio.get_event_loop()
    prompt = '>>> '
    itr = code.InteractiveInterpreter()
    while True:
        await cloop.sock_sendall(prompt)
        prompt = '... '
        newinput = b''
        while b'\n' not in newinput:
            newinput += await cloop.sock_recv()
        somecode += newinput
        if newinput.startswith(' '):
            prompt = '... '
            continue
        try:
            compcode = code.compile_command(somecode)
        except SyntaxError as e:
            await cloop.sock_sendall(repr(e).encode('utf8'))
            compcode = None
            somecode = ''
            prompt = '>>> '
        if compcode:
            itr.runcode(compcode)
            somecode = ''
            prompt = '>>> '

