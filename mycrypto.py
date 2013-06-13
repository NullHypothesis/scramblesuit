#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This module provides cryptographic functions not implemented in PyCrypto.

The implemented algorithms include HKDF-SHA256, HMAC-SHA256-128, (CS)PRNGs and
an interface for encryption and decryption using AES in counter mode.
"""

import Crypto.Hash.SHA256
import Crypto.Hash.HMAC
import Crypto.Util.Counter
import Crypto.Cipher.AES

import obfsproxy.transports.base as base
import obfsproxy.common.log as logging

import math
import os

import const


log = logging.get_obfslogger()


class HKDF_SHA256( object ):
    """
    Implements HKDF using SHA256: https://tools.ietf.org/html/rfc5869
    This class only implements the `expand' but not the `extract' stage since
    the provided PRK already exhibits strong entropy.
    """

    def __init__( self, prk, info="", length=32 ):

        self.HashLen = const.SHA256_DIGEST_LENGTH

        if length > (self.HashLen * 255):
            raise ValueError("The OKM's length cannot be larger than %d." %
                             (self.HashLen * 255))

        if len(prk) < self.HashLen:
            raise ValueError("The PRK must be at least %d bytes in length "
                             "(%d given)." % (self.HashLen, len(prk)))

        self.N = math.ceil(float(length) / self.HashLen)
        self.prk = prk
        self.info = info
        self.length = length
        self.ctr = 1
        self.T = ""


    def expand( self ):
        """Returns the expanded output key material which is calculated based
        on the given PRK, info and L."""

        tmp = ""

        # Prevent the accidental re-use of output keying material.
        if len(self.T) > 0:
            raise base.PluggableTransportError("HKDF-SHA256 OKM must not "
                                               "be re-used by application.")

        while self.length > len(self.T):
            tmp = Crypto.Hash.HMAC.new(self.prk, tmp + self.info +
                                       chr(self.ctr),
                                       Crypto.Hash.SHA256).digest()
            self.T += tmp
            self.ctr += 1

        return self.T[:self.length]



def HMAC_SHA256_128( key, msg ):
    """Returns the HMAC-SHA256-128 of the given `key' and `msg'."""

    assert(len(key) == const.SHA256_DIGEST_LENGTH)

    h = Crypto.Hash.HMAC.new(key, msg, Crypto.Hash.SHA256)

    # Return HMAC truncated to 128 out of 256 bits.
    return h.digest()[:16]



def strong_random( size ):
    """Returns `size' bytes of strong randomness which is suitable for
    cryptographic use."""

    return os.urandom(size)



def weak_random( size ):
    """Returns `size' bytes of weak randomness which can be used to pad
    application data but is not suitable for cryptographic use."""

    # TODO - Use a function which does not stress our entropy pool.
    return os.urandom(size)


class PayloadCrypter:
    """Encrypts plain Tor data using AES. The encrypted data is then passed on
    to the obfuscation component PayloadScrambler."""

    def __init__( self ):

        log.debug("Initialising payload crypter.")
        self.sessionKey = None
        self.crypter = None
        self.counter = None


    def setSessionKey( self, key, iv ):
        """Set the AES session key and initialise counter mode."""

        log.debug("Setting session key for AES-CTR 0x%s..." %
                  key.encode('hex')[:10])
        log.debug("Setting IV for AES-CTR 0x%s..." %
                  iv.encode('hex')[:10])

        self.sessionKey = key
        self.counter = Crypto.Util.Counter.new(128, initial_value = 
                                               long(iv.encode('hex'), 16))
        self.crypter = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CTR,
                                             counter=self.counter)


    def encrypt( self, data ):
        """Encrypts the given `data' using AES."""

        # Send unencrypted data if AES is not initialised yet.
        if self.crypter == None:
            return data
        else:
            return self.crypter.encrypt(data)


    # Encryption equals decryption in AES CTR.
    decrypt = encrypt
