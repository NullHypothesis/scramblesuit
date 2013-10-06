"""
This module provides code to handle ScrambleSuit protocol messages.

The exported classes and functions provide interfaces to handle protocol
messages, check message headers for validity and create protocol messages out
of application data.
"""

import obfsproxy.common.log as logging
import obfsproxy.common.serialize as serialize

import struct
import mycrypto
import const

log = logging.get_obfslogger()


def createProtocolMessages( data, flags=const.FLAG_PAYLOAD ):
    """
    Create protocol messages out of the given payload.

    The given `data' is turned into a list of protocol messages with the given
    `flags' set.  The list is then returned.  If possible, all messages fill
    the MTU.
    """

    messages = []

    while len(data) >= const.MPU:
        messages.append(ProtocolMessage(data[:const.MPU], flags=flags))
        data = data[const.MPU:]

    messages.append(ProtocolMessage(data, flags=flags))

    log.debug("Created %d protocol messages." % len(messages))

    return messages


def getFlagNames( flags ):
    """
    Return the flag names contained in the integer `flags' as string.

    This function is only useful for printing easy-to-read flag names in debug
    log messages.
    """

    names = ""

    if flags & (1 << 0):
        names += ",PAYLOAD"
    elif flags & (1 << 1):
        names += ",NEW_TICKET"
    elif flags & (1 << 2):
        names += ",PRNG_SEED"
    else:
        names += ",Undefined"

    return names[1:]


def isSane( totalLen, payloadLen, flags ):
    """
    Verifies whether the given header fields are sane.

    The values of the fields `totalLen', `payloadLen' and `flags' are checked
    for their sanity.  If they are in the expected range, `True' is returned.
    If any of these fields has an invalid value, `False' is returned.
    """

    def ok( length ):
        return True if (0 <= length <= const.MPU) else False

    log.debug("Message header: totalLen=%d, payloadLen=%d, flags"
              "=%s" % (totalLen, payloadLen, getFlagNames(flags)))

    validFlags = [
        const.FLAG_PAYLOAD,
        const.FLAG_NEW_TICKET,
        const.FLAG_PRNG_SEED,
    ]

    return ok(totalLen) and ok(payloadLen) and (flags in validFlags)


class ProtocolMessage( object ):

    """
    Represents a ScrambleSuit protocol message.

    This class provides methods to deal with protocol messages.  The methods
    make it possible to add padding as well as to encrypt and authenticate
    protocol messages.
    """

    def __init__( self, payload="", paddingLen=0, flags=const.FLAG_PAYLOAD ):
        """
        Initialises a ProtocolMessage object.
        """

        payloadLen = len(payload)
        assert((payloadLen + paddingLen) <= (const.MPU))

        self.hmac = ""
        self.totalLen = payloadLen + paddingLen
        self.payloadLen = payloadLen
        self.payload = payload
        self.flags = flags

    def encryptAndHMAC( self, crypter, HMACKey ):
        """
        Encrypt and authenticate this protocol message.

        This protocol message is encrypted using `crypter' and authenticated
        using `HMACKey'.  Finally, the encrypted message prepended by a
        HMAC-SHA256-128 is returned and ready to be sent over the wire.
        """

        encrypted = crypter.encrypt(serialize.htons(self.totalLen) +
                                    serialize.htons(self.payloadLen) +
                                    chr(self.flags) + self.payload +
                                    (self.totalLen - self.payloadLen) * '\0')

        hmac = mycrypto.HMAC_SHA256_128(HMACKey, encrypted)

        return hmac + encrypted

    def addPadding( self, paddingLen ):
        """
        Add padding to this protocol message.

        Padding is added to this protocol message.  The exact amount is
        specified by `paddingLen'.
        """

        # The padding must not exceed the message size.
        assert ((self.totalLen + paddingLen) <= const.MPU)

        if paddingLen == 0:
            return

        log.debug("Adding %d bytes of padding to %d-byte message." %
                  (paddingLen, const.HDR_LENGTH + self.totalLen))
        self.totalLen += paddingLen

    def __len__( self ):
        """
        Return the length of this protocol message.
        """

        return const.HDR_LENGTH + self.totalLen

# Alias class name in order to provide a more intuitive API.
new = ProtocolMessage
