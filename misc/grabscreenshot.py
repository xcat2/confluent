import base64
import pyghmi.redfish.command as ic
import pyghmi.util.webclient as webclient
import sys
import os
import time

def iterm_draw(databuf):
    datalen = len(databuf)
    data = base64.b64encode(databuf).decode('utf8')
    sys.stdout.write(
        '\x1b]1337;File=inline=1;size={}:'.format(datalen))
    sys.stdout.write(data)
    sys.stdout.write('\a')
    sys.stdout.write('\n')
    sys.stdout.flush()


i = ic.Command(sys.argv[1], os.environ['XCCUSER'], os.environ['XCCPASS'], verifycallback=lambda x: True)
i.get_health()
#url = '/download/Mini_ScreenShot.png?t={}'.format(int(time.time()*1000))
i.oem.wc.grab_json_response('/api/providers/rp_screenshot')
url = '/download/HostScreenShot.png'
fd = webclient.FileDownloader(i.oem.wc, url, sys.argv[2])
fd.start()
fd.join()
if sys.argv[3]:
    imgdata = open(sys.argv[2], 'rb').read()
    iterm_draw(imgdata)


