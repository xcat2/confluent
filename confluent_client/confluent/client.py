# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 IBM Corporation
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

try:
    import anydbm as dbm
except ImportError:
    import dbm
import csv
import errno
import fnmatch
import hashlib
import os
import shlex
import socket
import ssl
import sys
import confluent.tlvdata as tlvdata
import confluent.sortutil as sortutil

SO_PASSCRED = 16

_attraliases = {
    'bmc': 'hardwaremanagement.manager',
    'bmcuser': 'secret.hardwaremanagementuser',
    'switchuser': 'secret.hardwaremanagementuser',
    'bmcpass': 'secret.hardwaremanagementpassword',
    'switchpass': 'secret.hardwaremanagementpassword',
}

try:
    getinput = raw_input
except NameError:
    getinput = input


class NestedDict(dict):
    def __missing__(self, key):
        value = self[key] = type(self)()
        return value


def stringify(instr):
    # Normalize unicode and bytes to 'str', correcting for
    # current python version
    if isinstance(instr, bytes) and not isinstance(instr, str):
        return instr.decode('utf-8')
    elif not isinstance(instr, bytes) and not isinstance(instr, str):
        return instr.encode('utf-8')
    return instr


class Tabulator(object):
    def __init__(self, headers):
        self.headers = headers
        self.rows = []

    def add_row(self, row):
        self.rows.append(row)

    def get_table(self, order=None):
        i = 0
        fmtstr = ''
        separator = []
        for head in self.headers:
            if order and order == head:
                order = i
            neededlen = len(head)
            for row in self.rows:
                if len(row[i]) > neededlen:
                    neededlen = len(row[i])
            separator.append('-' * (neededlen + 1))
            fmtstr += '{{{0}:>{1}}}|'.format(i, neededlen + 1)
            i = i + 1
        fmtstr = fmtstr[:-1]
        yield fmtstr.format(*self.headers)
        yield fmtstr.format(*separator)
        if order is not None:
            for row in sorted(
                    self.rows,
                    key=lambda x: sortutil.naturalize_string(x[order])):
                yield fmtstr.format(*row)
        else:
            for row in self.rows:
                yield fmtstr.format(*row)

    def write_csv(self, output, order=None):
        output = csv.writer(output)
        output.writerow(self.headers)
        i = 0
        for head in self.headers:
            if order and order == head:
                order = i
            i = i + 1
        if order is not None:
            for row in sorted(
                    self.rows,
                    key=lambda x: sortutil.naturalize_string(x[order])):
                output.writerow(row)
        else:
            for row in self.rows:
                output.writerow(row)


def printerror(res, node=None):
    exitcode = 0
    if 'errorcode' in res:
        exitcode = res['errorcode']
    for node in res.get('databynode', {}):
        exitcode = res['databynode'][node].get('errorcode', exitcode)
        if 'error' in res['databynode'][node]:
            sys.stderr.write(
                '{0}: {1}\n'.format(node, res['databynode'][node]['error']))
            if exitcode == 0:
                exitcode = 1
    if 'error' in res:
        if node:
            sys.stderr.write('{0}: {1}\n'.format(node, res['error']))
        else:
            sys.stderr.write('{0}\n'.format(res['error']))
        if 'errorcode' not in res:
            exitcode = 1
    return exitcode


def cprint(txt):
    try:
        print(txt)
    except UnicodeEncodeError:
        print(txt.encode('utf8'))
    sys.stdout.flush()

def _parseserver(string):
    if ']:' in string:
        server, port = string[1:].split(']:')
    elif string[0] == '[':
        server = string[1:-1]
        port = '13001'
    elif ':' in string:
        server, port = string.split(':')
    else:
        server = string
        port = '13001'
    return server, port


class Command(object):
    def __init__(self, server=None):
        self._prevdict = None
        self._prevkeyname = None
        self.connection = None
        self._currnoderange = None
        self.unixdomain = False
        if server is None:
            if 'CONFLUENT_HOST' in os.environ:
                self.serverloc = os.environ['CONFLUENT_HOST']
            else:
                self.serverloc = '/var/run/confluent/api.sock'
        else:
            self.serverloc = server
        self.connected = False

    async def ensure_connected(self):
        if self.connected:
            return True
        if os.path.isabs(self.serverloc) and os.path.exists(self.serverloc):
            self._connect_unix()
            self.unixdomain = True
        elif self.serverloc == '/var/run/confluent/api.sock':
            raise Exception('Confluent service is not available')
        else:
            self._connect_tls()
        self.protversion = int((await tlvdata.recv(self.connection)).split(
            b'--')[1].strip()[1:])
        authdata = await tlvdata.recv(self.connection)
        if authdata['authpassed'] == 1:
            self.authenticated = True
        else:
            self.authenticated = False
        if not self.authenticated and 'CONFLUENT_USER' in os.environ:
            username = os.environ['CONFLUENT_USER']
            passphrase = os.environ['CONFLUENT_PASSPHRASE']
            await self.authenticate(username, passphrase)
        self.connected = True

    async def add_file(self, name, handle, mode):
        await self.ensure_connected()
        if self.protversion < 3:
            raise Exception('Not supported with connected confluent server')
        if not self.unixdomain:
            raise Exception('Can only add a file to a unix domain connection')
        tlvdata.send(self.connection, {'filename': name, 'mode': mode}, handle)

    async def authenticate(self, username, password):
        tlvdata.send(self.connection,
                     {'username': username, 'password': password})
        authdata = await tlvdata.recv(self.connection)
        if authdata['authpassed'] == 1:
            self.authenticated = True

    def add_precede_key(self, keyname):
        self._prevkeyname = keyname

    def add_precede_dict(self, dict):
        self._prevdict = dict

    def handle_results(self, ikey, rc, res, errnodes=None, outhandler=None):
        if 'error' in res:
            if errnodes is not None:
                errnodes.add(self._currnoderange)
            sys.stderr.write('Error: {0}\n'.format(res['error']))
            if 'errorcode' in res:
                return res['errorcode']
            else:
                return 1
        if 'databynode' not in res:
            return 0
        res = res['databynode']
        for node in res:
            if 'error' in res[node]:
                if errnodes is not None:
                    errnodes.add(node)
                sys.stderr.write('{0}: Error: {1}\n'.format(
                    node, res[node]['error']))
                if 'errorcode' in res[node]:
                    rc |= res[node]['errorcode']
                else:
                    rc |= 1
            elif ikey in res[node]:
                if 'value' in res[node][ikey]:
                    val = res[node][ikey]['value']
                elif 'isset' in res[node][ikey]:
                    val = '********' if res[node][ikey] else ''
                else:
                    val = repr(res[node][ikey])
                if self._prevkeyname and self._prevkeyname in res[node]:
                    cprint('{0}: {2}->{1}'.format(
                        node, val, res[node][self._prevkeyname]['value']))
                elif self._prevdict and node in self._prevdict:
                    cprint('{0}: {2}->{1}'.format(
                        node, val, self._prevdict[node]))
                else:
                    cprint('{0}: {1}'.format(node, val))
            elif outhandler:
                outhandler(node, res)
        return rc

    def simple_noderange_command(self, noderange, resource, input=None,
                                 key=None, errnodes=None, promptover=None, outhandler=None, **kwargs):
        try:
            self._currnoderange = noderange
            rc = 0
            if resource[0] == '/':
                resource = resource[1:]
            # The implicit key is the resource basename
            if key is None:
                ikey = resource.rpartition('/')[-1]
            else:
                ikey = key
            if input is None:
                for res in self.read('/noderange/{0}/{1}'.format(
                        noderange, resource)):
                    rc = self.handle_results(ikey, rc, res, errnodes, outhandler)
            else:
                self.stop_if_noderange_over(noderange, promptover)
                kwargs[ikey] = input
                for res in self.update('/noderange/{0}/{1}'.format(
                        noderange, resource), kwargs):
                    rc = self.handle_results(ikey, rc, res, errnodes, outhandler)
            self._currnoderange = None
            return rc
        except KeyboardInterrupt:
            cprint('')
            return 0
    
    def stop_if_noderange_over(self, noderange, maxnodes):
        if maxnodes is None:
            return
        nsize = self.get_noderange_size(noderange)
        if nsize > maxnodes:
            if nsize == 1:
                nodename = list(self.read(
                    '/noderange/{0}/nodes/'.format(noderange)))[0].get('item', {}).get('href', None)
                nodename = nodename[:-1]
                p = getinput('Command is about to affect node {0}, continue (y/n)? '.format(nodename))
            else:
                p = getinput('Command is about to affect {0} nodes, continue (y/n)? '.format(nsize))
            if p.lower() != 'y':
                sys.stderr.write('Aborting at user request\n')
                sys.exit(1)
                raise Exception("Aborting at user request")
        

    def get_noderange_size(self, noderange):
        numnodes = 0
        for node in self.read('/noderange/{0}/nodes/'.format(noderange)):
            if node.get('item', {}).get('href', None):
                numnodes += 1
            else:
                raise Exception("Error trying to size noderange {0}".format(noderange))
        return numnodes

    def simple_nodegroups_command(self, noderange, resource, input=None, key=None, **kwargs):
        try:
            rc = 0
            if resource[0] == '/':
                resource = resource[1:]
            # The implicit key is the resource basename
            if key is None:
                ikey = resource.rpartition('/')[-1]
            else:
                ikey = key
            if input is None:
                for res in self.read('/nodegroups/{0}/{1}'.format(
                        noderange, resource)):
                    rc = self.handle_results(ikey, rc, res)
            else:
                kwargs[ikey] = input
                for res in self.update('/nodegroups/{0}/{1}'.format(
                        noderange, resource), kwargs):
                    rc = self.handle_results(ikey, rc, res)
            return rc
        except KeyboardInterrupt:
            cprint('')
            return 0

    async def read(self, path, parameters=None):
        await self.ensure_connected()
        if not self.authenticated:
            raise Exception('Unauthenticated')
        async for rsp in send_request(
                'retrieve', path, self.connection, parameters):
            yield rsp

    async def update(self, path, parameters=None):
        await self.ensure_connected()
        if not self.authenticated:
            raise Exception('Unauthenticated')
        return await send_request('update', path, self.connection, parameters)

    async def create(self, path, parameters=None):
        await self.ensure_connected()
        if not self.authenticated:
            raise Exception('Unauthenticated')
        async for rsp in send_request('create', path, self.connection, parameters):
            yield rsp

    async def delete(self, path, parameters=None):
        await self.ensure_connected()
        if not self.authenticated:
            raise Exception('Unauthenticated')
        return await send_request('delete', path, self.connection, parameters)

    def _connect_unix(self):
        self.connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.connection.setsockopt(socket.SOL_SOCKET, SO_PASSCRED, 1)
        self.connection.connect(self.serverloc)

    def _connect_tls(self):
        server, port = _parseserver(self.serverloc)
        for res in socket.getaddrinfo(server, port, socket.AF_UNSPEC,
                                      socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            try:
                self.connection = socket.socket(af, socktype, proto)
                self.connection.setsockopt(
                    socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except:
                self.connection = None
                continue
            try:
                self.connection.settimeout(5)
                self.connection.connect(sa)
                self.connection.settimeout(None)
            except:
                raise
                self.connection.close()
                self.connection = None
                continue
            break
        if self.connection is None:
            raise Exception("Failed to connect to %s" % self.serverloc)
        #TODO(jbjohnso): server certificate validation
        clientcfgdir = os.path.join(os.path.expanduser("~"), ".confluent")
        try:
            os.makedirs(clientcfgdir)
        except OSError as exc:
            if not (exc.errno == errno.EEXIST and os.path.isdir(clientcfgdir)):
                raise
        cacert = os.path.join(clientcfgdir, "ca.pem")
        certreqs = ssl.CERT_REQUIRED
        knownhosts = False
        if not os.path.exists(cacert):
            cacert = None
            certreqs = ssl.CERT_NONE
            knownhosts = True
        self.connection = ssl.wrap_socket(self.connection, ca_certs=cacert,
                                          cert_reqs=certreqs)
        if knownhosts:
            certdata = self.connection.getpeercert(binary_form=True)
            fingerprint = 'sha512$' + hashlib.sha512(certdata).hexdigest()
            fingerprint = fingerprint.encode('utf-8')
            hostid = '@'.join((port, server))
            khf = dbm.open(os.path.join(clientcfgdir, "knownhosts"), 'c', 384)
            if hostid in khf:
                if fingerprint == khf[hostid]:
                    return
                else:
                    replace = getinput(
                        "MISMATCHED CERTIFICATE DATA, ACCEPT NEW? (y/n):")
                    if replace not in ('y', 'Y'):
                        raise Exception("BAD CERTIFICATE")
            cprint('Adding new key for %s:%s' % (server, port))
            khf[hostid] = fingerprint


async def send_request(operation, path, server, parameters=None):
    """This function iterates over all the responses
    received from the server.

    :param operation:  The operation to request, retrieve, update, delete,
                       create, start, stop
    :param path: The URI path to the resource to operate on
    :param server: The socket to send data over
    :param parameters:  Parameters if any to send along with the request
    """
    payload = {'operation': operation, 'path': path}
    if parameters is not None:
        payload['parameters'] = parameters
    await tlvdata.send(server, payload)
    result = await tlvdata.recv(server)
    while '_requestdone' not in result:
        try:
            yield result
        except GeneratorExit:
            while '_requestdone' not in result:
                result = await tlvdata.recv(server)
            raise
        result = await tlvdata.recv(server)


def attrrequested(attr, attrlist, seenattributes, node=None):
    for candidate in attrlist:
        truename = candidate
        if candidate.startswith('hm'):
            candidate = candidate.replace('hm', 'hardwaremanagement', 1)
        if candidate in _attraliases:
            candidate = _attraliases[candidate]
        if fnmatch.fnmatch(attr.lower(), candidate.lower()):
            if node is None:
                seenattributes.add(truename)
            else:
                seenattributes[node][truename] = True
            return True
        elif attr.lower().startswith(candidate.lower() + '.'):
            if node is None:
                seenattributes.add(truename)
            else:
                seenattributes[node][truename] = 1
            return True
    return False


def printattributes(session, requestargs, showtype, nodetype, noderange, options):
    path = '/{0}/{1}/attributes/{2}'.format(nodetype, noderange, showtype)
    return print_attrib_path(path, session, requestargs, options)

def _sort_attrib(k):
    if isinstance(k[1], dict) and k[1].get('sortid', None) is not None:
        return k[1]['sortid']
    return k[0]

def print_attrib_path(path, session, requestargs, options, rename=None, attrprefix=None):
    exitcode = 0
    seenattributes = NestedDict()
    allnodes = set([])
    for res in session.read(path):
        if 'error' in res:
            sys.stderr.write(res['error'] + '\n')
            exitcode = 1
            continue
        for node in sorted(res['databynode']):
            allnodes.add(node)
            for attr, val in sorted(res['databynode'][node].items(), key=_sort_attrib):
                if attr == 'error':
                    sys.stderr.write('{0}: Error: {1}\n'.format(node, val))
                    continue
                if attr == 'errorcode':
                    exitcode |= val
                    continue
                seenattributes[node][attr] = True
                if rename:
                    printattr = rename.get(attr, attr)
                else:
                    printattr = attr
                if attrprefix:
                    printattr = attrprefix + printattr
                currattr = res['databynode'][node][attr]
                if show_attr(attr, requestargs, seenattributes, options, node):
                    if 'value' in currattr:
                        if currattr['value'] is not None:
                            val = currattr['value']
                            if isinstance(val, list):
                                val = ','.join(val)
                            attrout = '{0}: {1}: {2}'.format(
                                node, printattr, val).strip()
                        else:
                            attrout = '{0}: {1}:'.format(node, printattr)
                    elif 'isset' in currattr:
                        if currattr['isset']:
                            attrout = '{0}: {1}: ********'.format(node,
                                                                  printattr)
                        else:
                            attrout = '{0}: {1}:'.format(node, printattr)
                    elif isinstance(currattr, dict) and 'broken' in currattr:
                        attrout = '{0}: {1}: *ERROR* BROKEN EXPRESSION: ' \
                                  '{2}'.format(node, printattr,
                                               currattr['broken'])
                    elif isinstance(currattr, list) or isinstance(currattr, tuple):
                        attrout = '{0}: {1}: {2}'.format(node, attr, ','.join(map(str, currattr)))
                    elif isinstance(currattr, dict):
                        dictout = []
                        for k, v in currattr.items:
                            dictout.append("{0}={1}".format(k, v))
                        attrout = '{0}: {1}: {2}'.format(node, printattr, ','.join(map(str, dictout)))
                    else:
                        cprint("CODE ERROR" + repr(attr))
                    try:
                        blame = options.blame
                    except AttributeError:
                        blame = False
                    if blame or (isinstance(currattr, dict) and 'broken' in currattr):
                        blamedata = []
                        if 'inheritedfrom' in currattr:
                            blamedata.append('inherited from group {0}'.format(
                                currattr['inheritedfrom']
                            ))
                        if 'expression' in currattr:
                            blamedata.append(
                                'derived from expression "{0}"'.format(
                                    currattr['expression']))
                        if blamedata:
                            attrout += ' (' + ', '.join(blamedata) + ')'
                    try:
                        comparedefault = options.comparedefault
                    except AttributeError:
                        comparedefault = False
                    if comparedefault:
                        try:
                            exclude = options.exclude
                        except AttributeError:
                            exclude = False
                        if ((requestargs and not exclude) or
                                (currattr.get('default', None) is not None and
                                currattr.get('value', None) is not None and
                                currattr['value'] != currattr['default'])):
                            cval = ','.join(currattr['value']) if isinstance(
                                currattr['value'], list) else currattr['value']
                            dval = ','.join(currattr['default']) if isinstance(
                                currattr['default'], list) else currattr['default']
                            cprint('{0}: {1}: {2} (Default: {3})'.format(
                                node, printattr, cval, dval))
                    else:

                        try:
                            details = options.detail
                        except AttributeError:
                            details = False
                        if details:
                            if currattr.get('help', None):
                                attrout += u' (Help: {0})'.format(
                                    currattr['help'])
                            if currattr.get('possible', None):
                                try:
                                    attrout += u' (Choices: {0})'.format(
                                        ','.join(currattr['possible']))
                                except TypeError:
                                    pass
                        cprint(attrout)
    somematched = set([])
    printmissing = set([])
    badnodes = NestedDict()
    if not exitcode:
        if requestargs:
            for attr in requestargs:
                for node in allnodes:
                    if attr in seenattributes[node]:
                        somematched.add(attr)
                    else:
                        badnodes[node][attr] = True
                        exitcode = 1
        for node in sortutil.natural_sort(badnodes):
            for attr in badnodes[node]:
                if attr in somematched:
                    sys.stderr.write(
                        'Error: {0} matches no valid value for {1}\n'.format(
                            attr, node))
                else:
                    printmissing.add(attr)
        for missing in printmissing:
            sys.stderr.write('Error: {0} not a valid attribute\n'.format(attr))
    return exitcode


def show_attr(attr, requestargs, seenattributes, options, node):
    try:
        reverse = options.exclude
    except AttributeError:
        reverse = False
    if requestargs is None or requestargs == []:
        return True
    processattr = attrrequested(attr, requestargs, seenattributes, node)
    if reverse:
        processattr = not processattr
    return processattr


def printgroupattributes(session, requestargs, showtype, nodetype, noderange, options):
    exitcode = 0
    seenattributes = set([])
    for res in session.read('/{0}/{1}/attributes/{2}'.format(nodetype, noderange, showtype)):
        if 'error' in res:
            sys.stderr.write(res['error'] + '\n')
            exitcode = 1
            continue
        for attr in res:
            seenattributes.add(attr)
            currattr = res[attr]
            if (requestargs is None or requestargs == [] or attrrequested(attr, requestargs, seenattributes)):
                if 'value' in currattr:
                    if currattr['value'] is not None:
                        attrout = '{0}: {1}: {2}'.format(
                            noderange, attr, currattr['value'])
                    else:
                        attrout = '{0}: {1}:'.format(noderange, attr)
                elif 'isset' in currattr:
                    if currattr['isset']:
                        attrout = '{0}: {1}: ********'.format(noderange, attr)
                    else:
                        attrout = '{0}: {1}:'.format(noderange, attr)
                elif isinstance(currattr, dict) and 'broken' in currattr:
                    attrout = '{0}: {1}: *ERROR* BROKEN EXPRESSION: ' \
                              '{2}'.format(noderange, attr,
                                           currattr['broken'])
                elif 'expression' in currattr:
                    attrout = '{0}: {1}:  (will derive from expression {2})'.format(noderange, attr, currattr['expression'])
                elif isinstance(currattr, list) or isinstance(currattr, tuple):
                    attrout = '{0}: {1}: {2}'.format(noderange, attr, ','.join(map(str, currattr)))
                elif isinstance(currattr, dict):
                    dictout = []
                    for k, v in currattr.items:
                        dictout.append("{0}={1}".format(k, v))
                    attrout = '{0}: {1}: {2}'.format(noderange, attr, ','.join(map(str, dictout)))
                else:
                    cprint("CODE ERROR" + repr(attr))
                cprint(attrout)
    if not exitcode:
        if requestargs:
            for attr in requestargs:
                if attr not in seenattributes:
                    sys.stderr.write('Error: {0} not a valid attribute\n'.format(attr))
                    exitcode = 1
    return exitcode

def updateattrib(session, updateargs, nodetype, noderange, options, dictassign=None):
    # update attribute
    exitcode = 0
    if options.clear:
        targpath = '/{0}/{1}/attributes/all'.format(nodetype, noderange)
        keydata = {}
        for attrib in updateargs[1:]:
            keydata[attrib] = None
        for res in session.update(targpath, keydata):
            if 'error' in res:
                if 'errorcode' in res:
                    exitcode = res['errorcode']
                sys.stderr.write('Error: ' + res['error'] + '\n')
        sys.exit(exitcode)
    elif hasattr(options, 'environment') and options.environment:
        for key in updateargs[1:]:
            key = key.replace('.', '_')
            value = os.environ.get(
                key, os.environ[key.upper()])
            # Let's do one pass to make sure that there's not a usage problem
        for key in updateargs[1:]:
            key = key.replace('.', '_')
            value = os.environ.get(
                key, os.environ[key.upper()])
            if (nodetype == "nodegroups"):
                exitcode = session.simple_nodegroups_command(noderange,
                                                             'attributes/all',
                                                             value, key)
            else:
                exitcode = session.simple_noderange_command(noderange,
                                                            'attributes/all',
                                                            value, key)
        sys.exit(exitcode)
    elif dictassign:
        for key in dictassign:
            if nodetype == 'nodegroups':
                exitcode = session.simple_nodegroups_command(
                    noderange, 'attributes/all', dictassign[key], key)
            else:
                exitcode = session.simple_noderange_command(
                    noderange, 'attributes/all', dictassign[key], key)
    else:
        if "=" in updateargs[1]:
            try:
                for val in updateargs[1:]:
                    val = val.split('=', 1)
                    if val[0][-1] in (',', '-', '^'):
                        key = val[0][:-1]
                        if val[0][-1] == ',':
                            value = {'prepend': val[1]}
                        elif val[0][-1] in ('-', '^'):
                            value = {'remove': val[1]}
                    else:
                        key = val[0]
                        value = val[1]
                    if (nodetype == "nodegroups"):
                        exitcode =  session.simple_nodegroups_command(noderange, 'attributes/all',
                                                                     value, key)
                    else:
                        exitcode = session.simple_noderange_command(noderange, 'attributes/all',
                                                                    value, key)
            except Exception:
                sys.stderr.write('Error: {0} not a valid expression\n'.format(str(updateargs[1:])))
                exitcode = 1
            sys.exit(exitcode)
    return exitcode


# So we try to prevent bad things from happening when globbing
# We tried to head this off at the shell, but the various solutions would end
# up breaking the shell in various ways (breaking pipe capability if using
# DEBUG, breaking globbing if in pipe, etc)
# Then we tried to parse the original commandline instead, however shlex isn't
# going to parse full bourne language (e.g. knowing that '|' and '>' and
# a world of other things would not be in our command line
# so finally, just make sure the noderange appears verbatim in the command line
# if we glob to something, then bash will change noderange and this should
# detect it and save the user from tragedy
def check_globbing(noderange):
    if not os.path.exists(noderange):
        return True
    rawargs = os.environ.get('CURRENT_CMDLINE', None)
    if rawargs:
        rawargs = shlex.split(rawargs)
        for arg in rawargs:
            if arg.startswith('$'):
                arg = arg[1:]
                if arg.endswith(';'):
                    arg = arg[:-1]
                arg = os.environ.get(arg, '$' + arg)
            if arg.startswith(noderange):
                break
        else:
            sys.stderr.write(
                'Shell glob conflict detected, specified target "{0}" '
                'not in command line, but is a file.  You can use "set -f" in '
                'bash or change directories such that there is no filename '
                'that would conflict.'
                '\n'.format(noderange))
            sys.exit(1)
