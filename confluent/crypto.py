# IBM(c) 2013

# This module provides cryptographic convenience functions, largely to be
# used by config.py to protect/unlock configuration as appropriopriate.
# The default behavior provides no meaningful protection, all encrypted
# values are linked to a master key that is stored in the clear.
# meanigful protection comes when the user elects to protect the key
# by passphrase and optionally TPM

import array
import confluent.config
import math
import os

from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256

_masterkey = None
_masterintegritykey = None



def _pbkdf2(passphrase, salt, iterations, size):
    # Implement the PBKDF2 standard algorithm for deriving key data
    # from a passphrase.  See internet for details
    blocks = int(math.ceil(size/32.0))  # Hardcoded to SHA256 behavior
    retkey = ""
    for block in xrange(blocks):
        citerations = iterations
        tsalt = salt + chr(block)
        currval = HMAC.new(passphrase, tsalt, SHA256).digest()
        currarray = array.array('L',currval)
        while citerations > 1:
            currval = HMAC.new(passphrase, currval).digest()
            nextarray = array.array('L',currval)
            for index in range(len(nextarray)):
                currarray[index] = currarray[index] ^ nextarray[index]
            currval = currarray.tostring()
            currarray = nextarray
            citerations = citerations - 1
        retkey += currval
    return retkey[:size]


def _derive_keys(passphrase, salt):
    #implement our specific combination of pbkdf2 transforms to get at
    #key.  We bump the iterations up because we can afford to
    tmpkey = _pbkdf2(passphrase, salt, 50000, 32)
    finalkey = _pbkdf2(tmpkey, salt, 50000, 96)
    return (finalkey[:32],finalkey[32:])


def _get_protected_key(keydict, passphrase):
    if keydict['unencryptedvalue']:
        return keydict['unencryptedvalue']
    # TODO(jbjohnso): check for TPM sealing
    if 'passphraseprotected' in keydict:
        if passphrase is None:
            raise Exception("Passphrase protected secret requires passhrase")
        for pp in keydict['passphraseprotected']:
            salt = pp[0]
            privkey, integkey = _derive_keys(passphrase, salt)
            return decrypt_value(pp[1:], key=privkey, integritykey=integkey)
    else:
        raise Exception("No available decryption key")


def _format_key(key, passphrase=None):
    if passphrase is not None:
        salt = os.urandom(32)
        privkey, integkey = _derive_keys(passphrase, salt)
        cval = crypt_value(key, key=privkey, integritykey=integkey)
        return {"passphraseprotected": cval}
    else:
        return {"unencryptedvalue": key}


def init_masterkey(passphrase=None):
    global _masterkey
    global _masterintegritykey
    cfgn = confluent.config.get_global('master_privacy_key')

    if cfgn:
        _masterkey = _get_protected_key(cfgn, passphrase=passphrase)
    else:
        _masterkey = os.urandom(32)
        confluent.config.set_global('master_privacy_key', _format_key(
            _masterkey,
            passphrase=passphrase))
    cfgn = confluent.config.get_global('master_integrity_key')
    if cfgn:
        _masterintegritykey = _get_protected_key(cfgn, passphrase=passphrase)
    else:
        _masterintegritykey = os.urandom(64)
        confluent.config.set_global('master_integrity_key', _format_key(
            _masterintegritykey,
            passphrase=passphrase))



def decrypt_value(cryptvalue,
                   key=_masterkey,
                   integritykey=_masterintegritykey):
    iv, cipherdata, hmac = cryptvalue
    if _masterkey is None or _masterintegritykey is None:
        init_masterkey()
    check_hmac = HMAC.new(_masterintegritykey, cipherdata, SHA256).digest()
    if hmac != check_hmac:
        raise Exception("bad HMAC value on crypted value")
    decrypter = AES.new(_masterkey, AES.MODE_CBC, iv)
    value = decrypter.decrypt(cipherdata)
    padsize = ord(value[-1])
    pad = value[-padsize:]
    # Note that I cannot grasp what could be done with a subliminal
    # channel in padding in this case, but check the padding anyway
    for padbyte in pad:
        if ord(padbyte) != padsize:
            raise Exception("bad padding in encrypted value")
    return value[0:-padsize]


def crypt_value(value,
                 key=_masterkey,
                 integritykey=_masterintegritykey):
    # encrypt given value
    # PKCS7 is the padding scheme to employ, if no padded needed, pad with 16
    # check HMAC prior to attempting decrypt
    if key is None or integritykey is None:
        init_masterkey()
        key=_masterkey
        integritykey=_masterintegritykey
    iv = os.urandom(16)
    crypter = AES.new(key, AES.MODE_CBC, iv)
    neededpad = 16 - (len(value) % 16)
    pad = chr(neededpad) * neededpad
    value = value + pad
    cryptval = crypter.encrypt(value)
    hmac = HMAC.new(integritykey, cryptval, SHA256).digest()
    return (iv, cryptval, hmac)
