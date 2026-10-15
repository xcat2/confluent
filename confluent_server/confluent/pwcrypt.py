# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2026 MEGWARE Computer Vertrieb und Service GmbH
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

# crypt(3) for hashing and checking the crypted.* attributes. crypt left the
# stdlib in 3.13, so prefer it, then the packaged replacements (legacycrypt,
# crypt_r), and finally call libcrypt directly, which is all the others do.
# Every Linux distribution ships libcrypt, while some package none of the
# Python modules (openSUSE Leap 16).

try:
    from crypt import crypt
except ImportError:
    try:
        from legacycrypt import crypt
    except ImportError:
        try:
            from crypt_r import crypt
        except ImportError:
            crypt = None

if crypt is None:
    import ctypes
    import ctypes.util
    import threading

    def _load_libcrypt():
        # libxcrypt is libcrypt.so.2 where it is built without the glibc
        # compatible API, libcrypt.so.1 otherwise
        names = [ctypes.util.find_library('crypt'), 'libcrypt.so.2',
                 'libcrypt.so.1']
        for name in names:
            if not name:
                continue
            try:
                lib = ctypes.CDLL(name, use_errno=True)
            except OSError:
                continue
            lib.crypt.argtypes = (ctypes.c_char_p, ctypes.c_char_p)
            lib.crypt.restype = ctypes.c_char_p
            return lib
        raise ImportError('no crypt module and no libcrypt found')

    _libcrypt = _load_libcrypt()
    # crypt(3) returns a pointer to a static buffer
    _lock = threading.Lock()

    def crypt(word, salt):
        with _lock:
            ret = _libcrypt.crypt(word.encode('utf8'), salt.encode('utf8'))
            if ret is None:
                errno = ctypes.get_errno()
                raise OSError(errno, 'crypt failed')
        return ret.decode('utf8')
