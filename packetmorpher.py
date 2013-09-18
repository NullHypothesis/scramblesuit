"""
Provides code to morph a chunk of data to a given probability distribution.

The class provides an interface to morph network packet lengths to a previously
generated probability distribution.  The packet lengths of the morphed network
data should then match the probability distribution.
"""

import random

import probdist
import const

import obfsproxy.common.log as logging

log = logging.get_obfslogger()

class PacketMorpher( object ):
    """Provides an interface to morph large chunks of bytes to a given target
    probability distribution. This is implemented by naively sampling the
    target probability distribution."""

    def __init__( self, dist=None ):
        """Initialise the PacketMorpher with a discrete probability
        distribution. If none is given, a distribution is randomly
        generated."""

        if dist:
            self.dist = dist
        else:
            self.dist = probdist.new(lambda: random.randint(const.HDR_LENGTH,
                                     const.MTU))

    def calcPadding( self, dataLen ):

        # The source and target length of the burst's last packet.
        dataLen = dataLen % const.MTU
        sampleLen = self.dist.randomSample()

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
