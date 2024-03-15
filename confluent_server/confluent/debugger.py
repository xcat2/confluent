import code
import sys

#this will ultimately fill the role of the 'backdoor' of eventlet

# since we have to asyncio up the input and output, we use InteractiveInterpreter and handle the
# input ourselves, since code is not asyncio friendly in and of itself
#code.InteractiveConsole().interact()
prompt = '>>> '
itr = code.InteractiveInterpreter()
while True:
    sys.stdout.write(prompt)
    prompt = '... '
    sys.stdout.flush()
    newinput = input()
    somecode += newinput + '\n'
    if newinput.startswith(' '):
        prompt = '... '
        continue
    try:
        compcode = code.compile_command(somecode)
    except SyntaxError as e:
        print(repr(e))
        compcode = None
        somecode = ''
        prompt = '>>> '
    if compcode:
        itr.runcode(compcode)
        somecode = ''
        prompt = '>>> '

