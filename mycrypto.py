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
        """
        Initialise a HKDF_SHA256 object.
        """

        self.hashLen = const.SHA256_DIGEST_LENGTH

        if length > (self.hashLen * 255):
            raise ValueError("The OKM's length cannot be larger than %d." %
                             (self.hashLen * 255))

        if len(prk) < self.hashLen:
            raise ValueError("The PRK must be at least %d bytes in length "
                             "(%d given)." % (self.hashLen, len(prk)))

        self.N = math.ceil(float(length) / self.hashLen)
        self.prk = prk
        self.info = info
        self.length = length
        self.ctr = 1
        self.T = ""

    def expand( self ):
        """
        Return the expanded output key material.

        The output key material is calculated based on the given PRK, info and
        L.
        """

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
    """
    Return the HMAC-SHA256-128 of the given `msg' authenticated by `key'.
    """

    assert(len(key) == const.SHA256_DIGEST_LENGTH)

    h = Crypto.Hash.HMAC.new(key, msg, Crypto.Hash.SHA256)

    # Return HMAC truncated to 128 out of 256 bits.
    return h.digest()[:16]


def strongRandom( size ):
    """
    Return `size' bytes of strong randomness suitable for cryptographic use.
    """

    return os.urandom(size)


def weakRandom( size ):
    """
    Return `size' bytes of weak randomness not suitable for cryptographic use.
    """

    # TODO - Use a function which does not stress our entropy pool.
    return os.urandom(size)


class PayloadCrypter:

    """
    Provides methods to encrypt data using AES in counter mode.

    This class provides methods to set a session key as well as an
    initialisation vector and to encrypt and decrypt data.
    """

    def __init__( self ):
        """
        Initialise a PayloadCrypter object.
        """

        log.debug("Initialising payload crypter.")

        self.sessionKey = None
        self.crypter = None
        self.counter = None

    def setSessionKey( self, key, iv ):
        """
        Set an AES session key and an initialisation vector.

        The given `key' and `iv' are used as AES counter mode key and
        initialisation vector.  Both, the key as well as the IV must come from
        a CSPRNG.
        """

        self.sessionKey = key

        log.debug("Setting IV for AES-CTR.")
        self.counter = Crypto.Util.Counter.new(128, initial_value =
                                               long(iv.encode('hex'), 16))

        log.debug("Setting session key for AES-CTR.")
        self.crypter = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CTR,
                                             counter=self.counter)

    def encrypt( self, data ):
        """
        Encrypts the given `data' using AES in counter mode.
        """

        assert self.crypter is not None

        return self.crypter.encrypt(data)

    # Encryption equals decryption in AES-CTR.
    decrypt = encrypt
