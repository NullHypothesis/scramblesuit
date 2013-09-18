"""
Provides code to morph a chunk of data to a given probability distribution.

The class provides an interface to morph a network packet's length to a
previously generated probability distribution.  The packet lengths of the
morphed network data should then match the probability distribution.
"""

import random

import probdist
import const

import obfsproxy.common.log as logging

log = logging.get_obfslogger()

class PacketMorpher( object ):

    """
    Implements methods to morph data to a target probability distribution.

    This class is used to modify ScrambleSuit's packet length distribution on
    the wire.  The class provides a method to determine the padding for packets
    smaller than the MTU.
    """

    def __init__( self, dist=None ):
        """
        Initialise the packet morpher with the given distribution `dist'.

        If `dist' is `None', a new discrete probability distribution is
        generated randomly.
        """

        if dist:
            self.dist = dist
        else:
            self.dist = probdist.new(lambda: random.randint(const.HDR_LENGTH,
                                                            const.MTU))

    def calcPadding( self, dataLen ):
        """
        Based on `dataLen', determines the padding for a network packet.

        ScrambleSuit morphs packets which are smaller than the link's MTU.
        This method draws a random sample from the probability distribution
        which is used to determine and return the padding for such packets.
        This effectively gets rid of Tor's 586-byte signature.
        """

        # The `is' and `should-be' length of the burst's last packet.
        dataLen = dataLen % const.MTU
        sampleLen = self.dist.randomSample()

        # Now determine the padding length which is in {0..MTU-1}.
        if sampleLen >= dataLen:
            padLen = sampleLen - dataLen
        else:
            padLen = (const.MTU - dataLen) + sampleLen

        log.debug("Morphing the last %d-byte packet to %d bytes by adding %d "
                  "bytes of padding." %
                  (dataLen % const.MTU, sampleLen, padLen))

        return padLen

# Alias class name in order to provide a more intuitive API.
new = PacketMorpher
