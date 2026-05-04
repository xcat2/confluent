import asyncio
from PIL import Image
import io
import numpy as np
import zlib

# This results in an RGBA organization of pixels
MYPIXFORMAT = bytearray([
    32,  # bits per pixel
    24,  # depth
    0,   # big endian
    1,   # true color
    0, 255,  # red max
    0, 255,  # green max
    0, 255,  # blue max
    16, 8, 0,     # red shift, green shift, blue shift
    0, 0, 0       # padding
])

class ByteStream:
    def __init__(self):
        self.buffer = b''

    def add_number(self, number, num_bytes):
        data = number.to_bytes(num_bytes, byteorder='big', signed=True)
        self.buffer += data

    def extend(self, data):
        self.buffer += data
    
    def get_bytes(self):
        return self.buffer
    
    def clear(self):
        self.buffer = b''

    def flush(self, writer):
        writer.write(self.buffer)
        self.clear()

class VNCClient:

    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
        return False
    
    @classmethod
    async def create(cls, url):
        self = cls()
        if url.startswith('unix://'):
            url = url.replace('unix://', '')
        if url.startswith('/'):
            self.reader, self.writer = await asyncio.open_unix_connection(url)
        elif url.startswith('@'):
            url = '\0' + url[1:]
            self.reader, self.writer = await asyncio.open_unix_connection(url)
        elif url.startswith('tcp://'):
            url = url.replace('tcp://', '')
            host, port = url.split(':')
            self.reader, self.writer = await asyncio.open_connection(host, int(port))
        else:
            raise ValueError('Unsupported URL: {}'.format(url))
        self.receiver = None
        self.framebuffer = None
        self.copytext = None
        self._updating = True
        self.decompressor = zlib.decompressobj()
        await self._do_vnc_handshake()
        return self
    
    async def send_keypresses(self, keys, modifierkeys=None):
        payload = ByteStream()
        for modkey in (modifierkeys or []):
            payload.add_number(4, 1)  # Key event
            payload.add_number(1, 1)  # Down
            payload.add_number(0, 2)  # Padding
            payload.add_number(modkey.value, 4)
        for key in keys:
            keynumber = key.value if hasattr(key, 'value') else key
            payload.add_number(4, 1)  # Key event
            payload.add_number(1, 1)  # Down
            payload.add_number(0, 2)  # Padding
            payload.add_number(keynumber, 4)
            payload.add_number(4, 1)  # Key event
            payload.add_number(0, 1)  # Up
            payload.add_number(0, 2)  # Padding
            payload.add_number(keynumber, 4)
        for modkey in (modifierkeys or []):
            payload.add_number(4, 1)  # Key event
            payload.add_number(0, 1)  # Up
            payload.add_number(0, 2)  # Padding
            payload.add_number(modkey.value, 4)
        payload.flush(self.writer)

    async def _read_number(self, num_bytes):
        data = await self.reader.readexactly(num_bytes)
        return int.from_bytes(data, byteorder='big', signed=True)

    def _write_number(self, number, num_bytes):
        data = number.to_bytes(num_bytes, byteorder='big', signed=True)
        self.writer.write(data)
        return data

    async def get_screenshot(self):
        while self._updating:
            await asyncio.sleep(0.1)
        await asyncio.sleep(0)
        if self.framebuffer is None:
            raise Exception('No framebuffer data available')
        self._updating = True
        return self.framebuffer.copy()

    async def _do_vnc_handshake(self):
        rfbver = await self.reader.readline()
        if not rfbver.startswith(b'RFB 003.008'):
            self.writer.close()
            await self.writer.wait_closed()
            raise Exception('Unsupported RFB version')
        self.writer.write(b'RFB 003.008\n')
        numsectypes = await self._read_number(1)
        if not numsectypes:
            self.writer.close()
            await self.writer.wait_closed()
            raise Exception('No security types supported by the server')
        sectypes = await self.reader.readexactly(numsectypes)
        sectypes = bytearray(sectypes)
        secresult = 1
        if 1 in sectypes:
            self.writer.write(b'\x01')
            await self.writer.drain()
            secresult = await self._read_number(4)  # Security result
        if secresult != 0:
            self.writer.close()
            await self.writer.wait_closed()
            raise Exception('VNC authentication failed')
        self.writer.write(b'\x01')  # Share display
        self.width = await self._read_number(2)
        self.height = await self._read_number(2)
        pixformat = await self.reader.readexactly(16)
        name_length = await self._read_number(4)
        self.name = await self.reader.readexactly(name_length)
        payload = ByteStream()
        if pixformat != MYPIXFORMAT:
            payload.add_number(0, 1)  # Set pixel format
            payload.add_number(0, 3)  # Padding
            payload.extend(MYPIXFORMAT)
            payload.flush(self.writer)
        self.receiver = asyncio.create_task(self._receive_loop())
        payload.add_number(2, 1)  # Set encodings
        payload.add_number(0, 1)  # Padding
        payload.add_number(4, 2)  # Number of encodings
        payload.add_number(6, 4)  # zlib
        payload.add_number(7, 4)  # tight
        payload.add_number(-223, 4) # desktopsize
        payload.add_number(-308, 4) # extended desktopsize
        payload.flush(self.writer)
        self._request_screen_update(incremental=False)
    
    def _request_screen_update(self, incremental=True):
        incremental = 1 if incremental else 0
        payload = ByteStream()
        payload.add_number(3, 1)  # Framebuffer update request
        payload.add_number(incremental, 1)  # Incremental
        payload.add_number(0, 2)  # x position
        payload.add_number(0, 2)  # y position
        payload.add_number(self.width, 2)  # width
        payload.add_number(self.height, 2)  # height
        payload.flush(self.writer)

    async def _receive_loop(self):
        while True:
            try:
                message_type = await self._read_number(1)
                if message_type == 0:  # Framebuffer update
                    await self._handle_framebuffer_update()
                elif message_type == 1:  # Set color map entries
                    raise NotImplementedError('Set color map entries not implemented')
                elif message_type == 2:  # Bell
                    pass
                elif message_type == 3:  # Server cut text
                    padding = await self._read_number(3)
                    length = await self._read_number(4)
                    self.copytext = await self.reader.readexactly(length)
                else:
                    raise Exception(f'Unknown message type: {message_type}')
            except Exception as e:
                print(f"Error in receive loop: {e}")
                break        

    async def _handle_framebuffer_update(self):
        _ = await self._read_number(1) # Padding
        num_rects = await self._read_number(2)
        self._updating = True
        for _ in range(num_rects):
            await self._handle_rectangle()
        self._updating = False
        self._request_screen_update(incremental=True)

    async def _handle_rectangle(self):
        if self.framebuffer == None:
            self.framebuffer = Image.new('RGBA', (self.width, self.height))
        x = await self._read_number(2)
        y = await self._read_number(2)
        width = await self._read_number(2)
        height = await self._read_number(2)
        encoding_type = await self._read_number(4)
        pixel_data = None
        if encoding_type == 6:
            compressed_data_length = await self._read_number(4)
            compressed_data = await self.reader.readexactly(compressed_data_length)
            # Decompress the data using zlib and store it in the framebuffer
            pixel_data = self.decompressor.decompress(compressed_data)
        elif encoding_type == 0:
            pixel_data = await self.reader.readexactly(width * height * 4)  # Assuming 32 bits per pixel
        if encoding_type in (-223, -308):  # desktopsize
            self.width = width
            self.height = height
            self.framebuffer = Image.new('RGBA', (self.width, self.height))
            if encoding_type == -308:
                nscreens = await self._read_number(1)
                _ = await self._read_number(3)  # padding
                for _ in range(nscreens):
                    _ = await self.reader.readexactly(16)  # screen info        
        elif pixel_data:
            pixel_data = np.frombuffer(pixel_data, dtype=np.uint8).reshape((height, width, 4)).copy()
            pixel_data[:, :, 3] = 0xff
            img = Image.fromarray(pixel_data, 'RGBA')
            self.framebuffer.paste(img, (x, y))
        elif encoding_type == 7:  # tight
            # Best document I could see was:
            # https://github.com/TurboVNC/tightvnc/blob/main/vnc_winsrc/rfb/rfbproto.h
            tightheader = await self._read_number(1)
            streamid = tightheader & 0x0F
            if streamid:
                raise NotImplementedError('tight encoding with streamid not implemented')
            comptype = (tightheader >> 4) & 0x0F
            if comptype != 9:
                raise NotImplementedError(f'tight encoding with comptype {comptype} not implemented')
            compressed_data_length = await self._read_tight_length()
            compressed_data = await self.reader.readexactly(compressed_data_length)
            jpgimg = io.BytesIO(compressed_data)
            img = Image.open(jpgimg)
            self.framebuffer.paste(img, (x, y))
        else:
            raise Exception(f'Unsupported encoding type: {encoding_type}')
    
    async def _read_tight_length(self):
        length = 0
        for i in range(3):
            byte = await self._read_number(1)
            length |= ((byte & 0x7F) << (i * 7))
            if not (byte & 0x80):
                break
        return length
    async def close(self):
        self.writer.close()
        await self.writer.wait_closed()