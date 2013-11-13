import unittest

import os
import util
import const
import mycrypto
import uniformdh
import scramblesuit
import base64

import Crypto.Hash.SHA256
import Crypto.Hash.HMAC

import obfsproxy.network.buffer as obfs_buf
import obfsproxy.common.transport_config as transport_config
import obfsproxy.transports.base as base

class CryptoTest( unittest.TestCase ):

    """
    The HKDF test cases are taken from the appendix of RFC 5869:
    https://tools.ietf.org/html/rfc5869
    """

    def setUp( self ):
        pass

    def extract( self, salt, ikm ):
        return Crypto.Hash.HMAC.new(salt, ikm, Crypto.Hash.SHA256).digest()

    def runHKDF( self, ikm, salt, info, prk, okm ):
        myprk = self.extract(salt, ikm)
        self.failIf(myprk != prk)
        myokm = mycrypto.HKDF_SHA256(myprk, info).expand()
        self.failUnless(myokm in okm)

    def test1_HKDF_TestCase1( self ):

        ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".decode('hex')
        salt = "000102030405060708090a0b0c".decode('hex')
        info = "f0f1f2f3f4f5f6f7f8f9".decode('hex')
        prk = ("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122e" + \
              "c844ad7c2b3e5").decode('hex')
        okm = ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db" + \
              "02d56ecc4c5bf34007208d5b887185865").decode('hex')

        self.runHKDF(ikm, salt, info, prk, okm)

    def test2_HKDF_TestCase2( self ):

        ikm = ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c" + \
               "1d1e1f202122232425262728292a2b2c2d2e2f30313233343536373839" + \
               "3a3b3c3d3e3f404142434445464748494a4b4c4d4e4f").decode('hex')
        salt =("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c" + \
               "7d7e7f808182838485868788898a8b8c8d8e8f90919293949596979899" + \
               "9a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf").decode('hex')
        info =("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcc" + \
               "cdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9" + \
               "eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").decode('hex')
        prk = ("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c1" + \
               "5fc244").decode('hex')
        okm = ("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19" + \
               "afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b83677" + \
               "93a9aca3db71cc30c58179ec3e87c14c01d5c1" + \
               "f3434f1d87").decode('hex')

        self.runHKDF(ikm, salt, info, prk, okm)

    def test3_HKDF_TestCase3( self ):
        ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".decode('hex')
        salt = ""
        info = ""
        prk = ("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377a" + \
               "c434c1c293ccb04").decode('hex')
        okm = ("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec" + \
               "3454e5f3c738d2d9d201395faa4b61a96c8").decode('hex')

        self.runHKDF(ikm, salt, info, prk, okm)

    def test4_CSPRNG( self ):
        self.failIf(mycrypto.strongRandom(10) == mycrypto.strongRandom(10))
        self.failIf(len(mycrypto.strongRandom(100)) != 100)

    def test5_AES( self ):
        plain = "this is a test"
        key = os.urandom(16)
        iv = os.urandom(8)

        crypter1 = mycrypto.PayloadCrypter()
        crypter1.setSessionKey(key, iv)
        crypter2 = mycrypto.PayloadCrypter()
        crypter2.setSessionKey(key, iv)

        cipher = crypter1.encrypt(plain)

        self.failIf(cipher == plain)
        self.failUnless(crypter2.decrypt(cipher) == plain)

class UniformDHTest( unittest.TestCase ):

    def setUp( self ):
        weAreServer = True
        self.udh = uniformdh.new("A" * const.SHARED_SECRET_LENGTH, weAreServer)

    def test1_createHandshake( self ):
        handshake = self.udh.createHandshake()
        self.failUnless((const.PUBLIC_KEY_LENGTH +
                         const.MARK_LENGTH +
                         const.HMAC_SHA256_128_LENGTH) <= len(handshake) <=
                        (const.MARK_LENGTH +
                         const.HMAC_SHA256_128_LENGTH +
                         const.MAX_PADDING_LENGTH))

    def test2_receivePublicKey( self ):
        buf = obfs_buf.Buffer(self.udh.createHandshake())

        def callback( masterKey ):
            self.failUnless(len(masterKey) == const.MASTER_KEY_LENGTH)

        self.failUnless(self.udh.receivePublicKey(buf, callback) == True)

        publicKey = self.udh.getRemotePublicKey()
        self.failUnless(len(publicKey) == const.PUBLIC_KEY_LENGTH)

    def test3_invalidHMAC( self ):
        # Make the HMAC invalid.
        handshake = self.udh.createHandshake()
        if handshake[-1] != 'a':
            handshake = handshake[:-1] + 'a'
        else:
            handshake = handshake[:-1] + 'b'

        buf = obfs_buf.Buffer(handshake)

        self.failIf(self.udh.receivePublicKey(buf, lambda x: x) == True)

class UtilTest( unittest.TestCase ):

    def test1_isValidHMAC( self ):
        self.failIf(util.isValidHMAC("A" * const.HMAC_SHA256_128_LENGTH,
                                     "B" * const.HMAC_SHA256_128_LENGTH,
                                     "X" * const.SHA256_LENGTH) == True)
        self.failIf(util.isValidHMAC("A" * const.HMAC_SHA256_128_LENGTH,
                                     "A" * const.HMAC_SHA256_128_LENGTH,
                                     "X" * const.SHA256_LENGTH) == False)

    def test2_locateMark( self ):
        self.failIf(util.locateMark("D", "ABC") != None)

        hmac = "X" * const.HMAC_SHA256_128_LENGTH
        mark = "A" * const.MARK_LENGTH
        payload = mark + hmac

        self.failIf(util.locateMark(mark, payload) == None)
        self.failIf(util.locateMark(mark, payload[:-1]) != None)


class MockArgs( object ):
    uniformDHSecret = sharedSecret = ext_cookie_file = dest = None
    mode = 'socks'


class ScrambleSuitTransportTest( unittest.TestCase ):

    def setUp( self ):
        config = transport_config.TransportConfig( )
        config.state_location = const.STATE_LOCATION
        args = MockArgs( )
        suit = scramblesuit.ScrambleSuitTransport
        suit.weAreServer = False

        self.suit = suit
        self.args = args
        self.config = config

        self.validSecret = base64.b32encode( 'A' * const.SHARED_SECRET_LENGTH )
        self.invalidSecret = 'a' * const.SHARED_SECRET_LENGTH

    def test1_validateExternalModeCli( self ):
        """Test with valid scramblesuit args and valid obfsproxy args."""
        self.args.uniformDHSecret = self.validSecret

        self.assertTrue(
            super( scramblesuit.ScrambleSuitTransport,
                   self.suit ).validate_external_mode_cli( self.args ))

        self.assertIsNone( self.suit.validate_external_mode_cli( self.args ) )

    def test2_validateExternalModeCli( self ):
        """Test with invalid scramblesuit args and valid obfsproxy args."""
        self.args.uniformDHSecret = self.invalidSecret

        with self.assertRaises( base.PluggableTransportError ):
            self.suit.validate_external_mode_cli( self.args )


if __name__ == '__main__':
    unittest.main()
