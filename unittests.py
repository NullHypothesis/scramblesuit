#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

import const
import uniformdh

import obfsproxy.network.buffer as obfs_buf

class UniformDHTest( unittest.TestCase ):

    def setUp( self ):
        weAreServer = True
        self.udh = uniformdh.new("A" * const.SHARED_SECRET_LENGTH, weAreServer)

    def test1_createHandshake( self ):
        handshake = self.udh.createHandshake()
        self.failUnless((const.PUBLIC_KEY_LENGTH +
                         const.MARKER_LENGTH +
                         const.HMAC_LENGTH) <= len(handshake) <=
                        (const.MARKER_LENGTH +
                         const.HMAC_LENGTH +
                         const.MAX_PADDING_LENGTH))

    def test2_receivePublicKey( self ):
        buf = obfs_buf.Buffer(self.udh.createHandshake())

        self.failUnless(self.udh.receivePublicKey(buf, lambda x: x) == True)

        publicKey = self.udh.getRemotePublicKey()
        self.failUnless(len(publicKey) == const.PUBLIC_KEY_LENGTH)

if __name__ == '__main__':
    unittest.main()
