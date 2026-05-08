# Copyright 2015-2019 Lenovo
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

# This provides ability to do HTTPS in a manner like ssh host keys for the
# sake of typical internal management devices.  Compatibility back to python
# 2.6 as is found in commonly used enterprise linux distributions.

import asyncio
import base64
import copy
import gzip
import io
import json
import os
import socket
import ssl
import threading
import traceback

from yarl import URL
import aiohmi.exceptions as pygexc


import aiohttp
from aiohttp.cookiejar import CookieJar

import http.client as httplib
import http.cookies as Cookie

# Used as the separator for form data

# We will frequently be dealing with the same data across many instances,
# consolidate forms to single memory location to get benefits..
uploadforms = {}

class CustomVerifier(aiohttp.Fingerprint):
    def __init__(self, verifycallback):
        self._certverify = verifycallback

    def check(self, transport):
        sslobj = transport.get_extra_info("ssl_object")
        cert = sslobj.getpeercert(binary_form=True)
        try:
            if not self._certverify(cert):
                raise pygexc.UnrecognizedCertificate('Unknown certificate',
                                                     cert)
        except Exception:
            transport.close()
            raise

class Downloader:
    @classmethod
    def create(cls, filehandle):
        self = cls()
        self.contentlen = None
        self._completed = False
        self._filehandle = filehandle
        self._xfertask = None
        self.exc = None
        return self

    async def get_progress(self):
        if self.contentlen is None:
            return -0.5
        offset = None
        retries = 100
        while offset is None:
            if self._completed:
                return 1.0
            try:
                offset = self._filehandle.tell()
            except ValueError:
                retries -= 1
                if retries <= 0:
                    return -0.5
                await asyncio.sleep(0.01)
        return float(offset) / float(self.contentlen)
    
    def mark_completed(self, fut):
        self._completed = True

    def set_task(self, task):
        self._xfertask = task

    def completed(self):
        return self._completed

    async def join(self, timeout=None):
        if self._xfertask is None:
            return
        if timeout is None:
            await self._xfertask
        else:
            await asyncio.wait_for(asyncio.shield(self._xfertask), timeout=timeout)

class Uploader(Downloader):
    @classmethod
    async def create(cls, filename, data=None, formname=None,
                 otherfields=(), formwrap=True):
        self = cls()
        self._response = None
        self._statuscode = None
        self._xfertask = None
        self._completed = False
        self._rspheaders = None
        self.rsp = ''
        self.rspstatus = 500
        self.filename = filename
        if data:
            self.data = data
        else:
            self.data = open(filename, 'rb')
        self.formname = formname
        self.otherfields = otherfields
        self.ulheaders = {}
        if formwrap:
            guf = await get_upload_form(
                filename, self.data, formname, otherfields)
            self._upbuffer = io.BytesIO(guf[0])
            self._boundary = guf[1]
            self.ulsize = len(uploadforms[filename][0])
            self.ulheaders['Content-Type'] = 'multipart/form-data; boundary={0}'.format(
                self._boundary.decode('utf-8'))
            self.ulheaders['Content-Size'] = str(self.ulsize)
        else:
            canseek = True
            try:
                curroff = self.data.tell()
            except Exception:
                canseek = False
                databytes = await asyncio.to_thread(self.data.read)
                self.ulsize = len(databytes)
                self._upbuffer = io.BytesIO(databytes)
            if canseek:
                self.data.seek(0, 2)
                self.ulsize = self.data.tell() - curroff
                self.data.seek(curroff, 0)
                self._upbuffer = self.data
            self.ulheaders['Content-Length'] = str(self.ulsize)
            self.ulheaders['Content-Type'] = 'application/octet-stream'
        return self
    
    def set_response(self, statuscode, response, headers):
        self._statuscode = statuscode
        self._response = response
        self._rspheaders = headers

    def get_response(self):
        return self._statuscode, self._response, self._rspheaders
    
    def get_buffer(self):
        return self._upbuffer
    
    def get_headers(self):
        return self.ulheaders
    
    def get_size(self):
        return self.ulsize
    
    def close(self):
        if self.filename in uploadforms:
            try:
                del uploadforms[self.filename]
            except KeyError:
                pass
        try:
            self.data.close()
        except Exception:
            pass

    async def get_progress(self):
        if self._completed:
            return 1.0
        if self._xfertask is None:
            return 0.0

        totalen = self.get_size()
        if totalen is None:
            return -0.5
        offset = None
        tries = 100
        while offset is None:
            if self._completed:
                return 1.0
            if self._xfertask is None:
                return 0.0
            try:
                offset = self._upbuffer.tell()
            except ValueError:
                await asyncio.sleep(0.01)
                tries -= 1
                if tries <= 0:
                    return -0.5
        return float(offset) / float(totalen)

def make_downloader(webconn, url, dlfile):
    if isinstance(dlfile, str):
        dlfile = open(dlfile, 'wb')
    dler = Downloader.create(dlfile)
    tsk = asyncio.create_task(webconn.download(url, dlfile, dler))
    dler.set_task(tsk)
    tsk.add_done_callback(dler.mark_completed)
    return dler

async def make_uploader(webconn, url, filename, data=None, formname=None,
                 otherfields=(), formwrap=True):
    uler = await Uploader.create(filename, data, formname, otherfields, formwrap)
    tsk = asyncio.create_task(webconn.upload(
        url, filename, uler.get_buffer(), uploader=uler))
    uler.set_task(tsk)
    tsk.add_done_callback(uler.mark_completed)
    return uler
    

    

async def get_upload_form(filename, data, formname, otherfields, boundary=None):
    if not boundary:
        boundary = base64.urlsafe_b64encode(os.urandom(54))[:66] 
    ffilename = filename.split('/')[-1]
    if not formname:
        formname = ffilename
    while uploadforms.get(filename, None) == 'pending':
        await asyncio.sleep(0.1)
    try:
        return uploadforms[filename]
    except KeyError:
        uploadforms[filename] = 'pending'
        try:
            data = await asyncio.to_thread(data.read)
        except AttributeError:
            pass
        return await asyncio.to_thread(assign_upload_form, filename, ffilename, data, formname, otherfields, boundary)

def assign_upload_form(filename, ffilename, data, formname, otherfields, boundary=None):
        form = b''
        for ofield in otherfields:
            tfield = otherfields[ofield]
            xtra=''
            if isinstance(tfield, dict):
                tfield = json.dumps(tfield)
                xtra = '\r\nContent-Type: application/json'
            form += (b'--' + boundary
                     + '\r\nContent-Disposition: form-data; '
                       'name="{0}"{1}\r\n\r\n{2}\r\n'.format(
                           ofield, xtra, tfield).encode('utf-8'))
        form += (b'--' + boundary
                + '\r\nContent-Disposition: form-data; '
                  'name="{0}"; filename="{1}"\r\n'.format(
                      formname, ffilename).encode('utf-8'))
        form += b'Content-Type: application/octet-stream\r\n\r\n' + data
        form += b'\r\n--' + boundary + b'--\r\n'
        uploadforms[filename] = form, boundary
        return uploadforms[filename]


class WebConnection:
    def __init__(self, host, port, verifycallback=None, timeout=None):
        self.port = port
        self.thehost = host
        if ':' in host and '[' not in host:
            self.host = f'[{host}]'
        else:
            self.host = host
        if verifycallback:
            self.ssl = CustomVerifier(verifycallback)
        else:
            self.ssl = None
        self.verifycallback = verifycallback
        if isinstance(timeout, (int, float)):
            self.timeout = aiohttp.ClientTimeout(total=timeout)
        elif timeout is None:
            self.timeout = aiohttp.client.DEFAULT_TIMEOUT
        else:
            self.timeout = timeout 
        self.stdheaders = {}
        if '[' not in host and '%' in host:
            self.stdheaders['Host'] = '[' + host.split('%', 1)[0] + ']'
        self.cookies = CookieJar(quote_cookie=False, unsafe=True)

    def set_timeout(self, timeout):
        if isinstance(timeout, (int, float)):
            self.timeout = aiohttp.ClientTimeout(total=timeout)
        else:
            self.timeout = timeout
    
    def get_timeout(self):
        return self.timeout
    
    def set_header(self, key, value):
        self.stdheaders[key] = value

    def dupe(self, timeout=None):
        newwc = WebConnection(self.host, self.port,
                              verifycallback=self.verifycallback, timeout=timeout or self.timeout)
        newwc.stdheaders = self.stdheaders.copy()
        newwc.cookies = CookieJar(quote_cookie=False, unsafe=True)
        for cookie in self.cookies:
            newwc.cookies.update_cookies(
                {cookie.key: cookie.value}, response_url=URL(f'https://{self.host}:{self.port}/'))
        return newwc

    async def request(
            self, method, url, body=None, headers=None, referer=None):
        if headers is None:
            headers = self.stdheaders.copy()
        else:
            headers = headers.copy()
        if method == 'GET' and 'Content-Type' in headers:
            del headers['Content-Type']
        if method == 'POST' and body and 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        if body and 'Content-Length' not in headers:
            headers['Content-Length'] = len(body)
        if referer:
            headers['referer'] = referer
        method = method.lower()
        async with aiohttp.ClientSession(
                f'https://{self.host}:{self.port}', cookie_jar=self.cookies, timeout=self.timeout) as session:
            thefunc = getattr(session, method)
            kwargs = {}
            if isinstance(body, dict):
                kwargs['json'] = body
            elif body:
                kwargs['data'] = body
            async with thefunc(url, headers=headers, ssl=self.ssl, **kwargs) as rsp:
                pass

    def set_basic_credentials(self, username, password):
        if isinstance(username, bytes) and not isinstance(username, str):
            username = username.decode('utf-8')
        if isinstance(password, bytes) and not isinstance(password, str):
            password = password.decode('utf-8')
        authinfo = ':'.join((username, password))
        if not isinstance(authinfo, bytes):
            authinfo = authinfo.encode('utf-8')
        authinfo = base64.b64encode(authinfo)
        if not isinstance(authinfo, str):
            authinfo = authinfo.decode('utf-8')
        self.stdheaders['Authorization'] = 'Basic {0}'.format(authinfo)

    async def grab_json_response(self, url, data=None, referer=None, headers=None):
        self.lastjsonerror = None
        body, status = await self.grab_json_response_with_status(
            url, data, referer, headers)
        if status == 200:
            return body
        self.lastjsonerror = body
        return {}

    async def grab_json_response_with_status(self, url, data=None, referer=None,
                                        headers=None, method=None):
        rsp, status, hdrs = await self.grab_response_with_status(url, data, referer, headers, method, expect_type='json')
        return rsp, status

    async def grab_response_with_status(self, url, data=None, referer=None,
                                        headers=None, method=None, expect_type=None):
        if not headers:
            headers = self.stdheaders.copy()
        else:
            headers = headers.copy()
        if referer:
            headers['referer'] = referer
        if not method:
            method = 'POST' if data is not None else 'GET'
        method = method.lower()
        if 'Content-Type' in headers and method.lower() in ('get', 'delete'):
            del headers['Content-Type']
        async with aiohttp.ClientSession(f'https://{self.host}:{self.port}', cookie_jar=self.cookies, timeout=self.timeout) as session:
            thefunc = getattr(session, method)
            kwargs = {}
            if isinstance(data, dict):
                kwargs['json'] = data
                if 'Content-Type' not in headers:
                    headers['Content-Type'] = 'application/json'
            elif data is not None:
                kwargs['data'] = data
            async with thefunc(url, headers=headers, ssl=self.ssl, **kwargs) as rsp:
                if rsp.status >= 200 and rsp.status < 300:
                    if expect_type == 'json':
                        return await rsp.json(content_type=''), rsp.status, rsp.headers
                    elif expect_type == 'text':
                        return await rsp.text(), rsp.status, rsp.headers
                    else:
                        return await rsp.read(), rsp.status, rsp.headers
                else:
                    return await rsp.read(), rsp.status, rsp.headers

    async def download(self, url, dlfile, downloader=None):
        """Download a file to filename or file object

        """
        if isinstance(dlfile, str):
            dlfile = open(dlfile, 'wb')
        dlheaders = self.stdheaders.copy()
        if 'Accept-Encoding' in dlheaders:
            del dlheaders['Accept-Encoding']
        async with aiohttp.ClientSession(f'https://{self.host}:{self.port}', cookie_jar=self.cookies, timeout=self.timeout) as session:
            async with session.get(url, headers=dlheaders, ssl=self.ssl) as rsp:
                if downloader:
                    downloader.contentlen = rsp.headers.get('content-length', None)
                    try:
                        downloader.contentlen = int(downloader.contentlen)
                    except Exception:
                        downloader.contentlen = None
                async for chunk in rsp.content.iter_chunked(16384):
                    dlfile.write(chunk)
        dlfile.close()

    async def upload(self, url, ulfile, data=None, uploader=None):
        upheaders = self.stdheaders.copy()
        if uploader:
            upheaders.update(uploader.get_headers())
            data = uploader.get_buffer()
        else:
            raise Exception("Not implemented without uploader handler")
        async with aiohttp.ClientSession(f'https://{self.host}:{self.port}', cookie_jar=self.cookies, timeout=self.timeout) as session:
            async with session.post(url, headers=upheaders, ssl=self.ssl, data=data) as rsp:
                if rsp.status >= 200 and rsp.status < 300:
                    expect_type = rsp.headers.get('Content-Type', '')
                    if 'json' in expect_type:
                        uploader.set_response(rsp.status, await rsp.json(content_type=''), rsp.headers)
                    elif 'text' in expect_type:
                        uploader.set_response(rsp.status, await rsp.text(), rsp.headers)
                    else:
                        uploader.set_response(rsp.status, await rsp.read(), rsp.headers)
                else:
                    uploader.set_response(rsp.status, await rsp.read(), rsp.headers)
        if uploader:
            uploader.close()
            return uploader._statuscode

