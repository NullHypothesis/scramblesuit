#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This module implements a class to deal with Uniform Diffie-Hellman handshakes.

The class `UniformDH' is used by the server as well as by the client to handle
the Uniform Diffie-Hellman handshake used by ScrambleSuit.
"""

import const
import random
import binascii

import util
import mycrypto

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
            self.udh = UniformDHPublicKey()

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
            self.udh = UniformDHPublicKey()
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

# Note that the following code is taken from obfsproxy/transports/obfs3_dh.py.
# The code was modified to use the 4096-bit MODP group instead of the 1536-bit
# group used in obfs3 since ScrambleSuit aims for a security level of 128 bits.

def int_to_bytes(lvalue, width):
    fmt = '%%.%dx' % (2*width)
    return binascii.unhexlify(fmt % (lvalue & ((1L<<8*width)-1)))

class UniformDHPublicKey( object ):
    """
    This is a class that implements a DH handshake that uses public
    keys that are indistinguishable from 512-byte random strings.

    The idea (and even the implementation) was suggested by Ian
    Goldberg in:
    https://lists.torproject.org/pipermail/tor-dev/2012-December/004245.html
    https://lists.torproject.org/pipermail/tor-dev/2012-December/004248.html

    Attributes:
    mod, the modulus of our DH group.
    g, the generator of our DH group.
    group_len, the size of the group in bytes.

    priv_str, a byte string representing our DH private key.
    priv, our DH private key as an integer.
    pub_str, a byte string representing our DH public key.
    pub, our DH public key as an integer.
    shared_secret, our DH shared secret.
    """

    # 4096-bit MODP Group from RFC3526
    mod = int(
        """FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
           29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
           EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
           E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
           EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
           C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
           83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
           670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
           E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
           DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
           15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
           ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
           ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
           F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
           BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
           43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7
           88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA
           2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6
           287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED
           1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9
           93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199
           FFFFFFFF FFFFFFFF""".replace(' ','').replace('\n','').replace('\t',''), 16)
    g = 2
    group_len = 512 # bytes (4096-bits)

    def __init__(self):
        # Generate private key
        self.priv_str = mycrypto.strongRandom(self.group_len)
        self.priv = int(binascii.hexlify(self.priv_str), 16)

        # Make the private key even
        flip = self.priv % 2
        self.priv -= flip

        # Generate public key
        self.pub = pow(self.g, self.priv, self.mod)
        if flip == 1:
            self.pub = self.mod - self.pub
        self.pub_str = int_to_bytes(self.pub, self.group_len)

        self.shared_secret = None

    def get_public(self):
        return self.pub_str

    def get_secret(self, their_pub_str):
        """
        Given the public key of the other party as a string of bytes,
        calculate our shared secret.

        This might raise a ValueError since 'their_pub_str' is
        attacker controlled.
        """
        their_pub = int(binascii.hexlify(their_pub_str), 16)

        self.shared_secret = pow(their_pub, self.priv, self.mod)
        return int_to_bytes(self.shared_secret, self.group_len)
