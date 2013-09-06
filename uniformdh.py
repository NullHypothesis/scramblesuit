#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This module implements a class to deal with Uniform Diffie-Hellman handshakes.

The class `UniformDH' is used by the server as well as by the client to handle
the Uniform Diffie-Hellman handshake used by ScrambleSuit.
"""

import const
import random

import util
import mycrypto

import obfsproxy.transports.obfs3_dh as obfs3_dh
import obfsproxy.transports.base as base
import obfsproxy.common.log as logging

log = logging.get_obfslogger()

class UniformDH( object ):

    """
    Provide methods to deal with Uniform Diffie-Hellman handshakes.

    The class provides methods to extract public keys and to generate public
    keys wrapped in a valid UniformDH handshake.
    """

    def __init__( self, sharedSecret, weAreServer ):
        """
        Initialise a UniformDH object.
        """

        # `True' if we are the server; `False' otherwise.
        self.weAreServer = weAreServer

        # The shared UniformDH secret.
        self.sharedSecret = sharedSecret

        # Cache a UniformDH public key until it's added to the replay table.
        self.remotePublicKey = None

        # Uniform Diffie-Hellman object (implemented in obfs3_dh.py).
        self.udh = None

    def getRemotePublicKey( self ):
        """
        Return the cached remote UniformDH public key.
        """

        return self.remotePublicKey

    def receivePublicKey( self, data, callback ):
        """
        Extract the public key and invoke a callback with the master secret.

        First, the UniformDH public key is extracted out of `data'.  Then, the
        shared master secret is computed and `callback' is invoked with the
        master secret as argument.  If any of this fails, `False' is returned.
        """

        # Extract the public key sent by the remote host.
        remotePublicKey = self._extractPublicKey(data)
        if not remotePublicKey:
            return False

        if self.weAreServer:
            self.remotePublicKey = remotePublicKey
            # As server, we need a DH object; as client, we already have one.
            self.udh = obfs3_dh.UniformDH()

        assert self.udh is not None

        try:
            masterKey = self.udh.get_secret(remotePublicKey)
        except ValueError:
            raise base.PluggableTransportError("Corrupted public key.")

        # Truncate remainder of 1536-bit UniformDH group.
        masterKey = masterKey[:const.MASTER_KEY_LENGTH]

        # Derive the session keys from the newly obtained master key.
        callback(masterKey)

        return True

    def _extractPublicKey( self, data ):
        """
        Extract and return a UniformDH public key out of `data'.

        Before the public key is touched, the HMAC is verified.  If the HMAC is
        invalid or some other error occurs, `False' is returned.  Otherwise,
        the public key is returned.  The extracted data is finally drained from
        the given `data' object.
        """

        assert self.sharedSecret is not None

        # Do we already have the minimum amount of data?
        if len(data) < (const.PUBLIC_KEY_LENGTH + const.MARKER_LENGTH +
                        const.HMAC_LENGTH):
            return False

        log.debug("Attempting to extract UniformDH public key out of %d bytes "
                  "of data." % len(data))

        handshake = data.peek()

        # First, find the marker to efficiently locate the HMAC.
        publicKey = handshake[:const.PUBLIC_KEY_LENGTH]
        marker = mycrypto.HMAC_SHA256_128(self.sharedSecret,
                                          self.sharedSecret + publicKey)

        index = util.locateMarker(marker, handshake)
        if not index:
            return False

        # Now that we know where the authenticating HMAC is: verify it.
        hmacStart = index + const.MARKER_LENGTH
        existingHMAC = handshake[hmacStart : (hmacStart + const.HMAC_LENGTH)]
        myHMAC = mycrypto.HMAC_SHA256_128(self.sharedSecret,
                                          handshake[0 : hmacStart] +
                                          util.getEpoch())

        if not util.isValidHMAC(myHMAC, existingHMAC, self.sharedSecret):
            return False

        data.drain(index + const.MARKER_LENGTH + const.HMAC_LENGTH)

        return handshake[:const.PUBLIC_KEY_LENGTH]

    def createHandshake( self ):
        """
        Create and return a ready-to-be-sent UniformDH handshake.

        The returned handshake data includes the public key, pseudo-random
        padding, the marker and the HMAC.  If a UniformDH object has not been
        initialised yet, a new instance is created.
        """

        assert self.sharedSecret is not None

        log.debug("Creating UniformDH handshake message.")

        if self.udh is None:
            self.udh = obfs3_dh.UniformDH()
        publicKey = self.udh.get_public()

        assert (const.MAX_PADDING_LENGTH - const.PUBLIC_KEY_LENGTH) >= 0

        # Subtract the length of the public key to make the handshake on
        # average as long as a redeemed ticket.  That should thwart statistical
        # length-based attacks.
        padding = mycrypto.strongRandom(random.randint(0,
                                        const.MAX_PADDING_LENGTH -
                                        const.PUBLIC_KEY_LENGTH))

        # Add a marker which enables efficient location of the HMAC.
        marker = mycrypto.HMAC_SHA256_128(self.sharedSecret,
                                          self.sharedSecret + publicKey)

        # Authenticate the handshake including the current approximate epoch.
        mac = mycrypto.HMAC_SHA256_128(self.sharedSecret,
                                       publicKey + padding + marker +
                                       util.getEpoch())

        return publicKey + padding + marker + mac

# Alias class name in order to provide a more intuitive API.
new = UniformDH
