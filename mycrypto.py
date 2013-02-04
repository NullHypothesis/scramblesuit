#!/usr/bin/env python
# -*- coding: utf-8 -*-

import Crypto.Hash.SHA256
import Crypto.Hash.HMAC

import obfsproxy.transports.base as base

import math
import os

# Digest size of SHA256 (in bytes).
SHA256_DIGEST_SIZE = 32


class HKDF_SHA256( object ):
	"""
	Implements HKDF using SHA256: https://tools.ietf.org/html/rfc5869
	This class only implements the `expand' but not the `extract' stage.
	"""

	def __init__( self, prk, info="", length=32 ):

		self.HashLen = 32

		if length > (self.HashLen * 255):
			raise ValueError("The OKM's length cannot be larger than %d." % \
					(self.HashLen * 255))

		if len(prk) < self.HashLen:
			raise ValueError("The PRK must be at least %d bytes in length " \
					"(%d given)." % (self.HashLen, len(prk)))

		self.N = math.ceil(float(length) / self.HashLen)
		self.prk = prk
		self.info = info
		self.length = length
		self.ctr = 1
		self.T = ""


	def expand( self ):
		"""Expands, based on PRK, info and L, the given input material to the
		output key material."""

		tmp = ""

		# Prevent the accidental re-use of output keying material.
		if len(self.T) > 0:
			raise base.PluggableTransportError("HKDF-SHA256 OKM must not " \
					"be re-used by application.")

		while self.length > len(self.T):
			tmp = Crypto.Hash.HMAC.new(self.prk, tmp + self.info + \
					chr(self.ctr), Crypto.Hash.SHA256).digest()
			self.T += tmp
			self.ctr += 1

		return self.T[:self.length]



def MyHMAC_SHA256_128( key, msg ):
	"""Wraps Crypto.Hash's HMAC."""

	assert(len(key) == SHA256_DIGEST_SIZE)

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

	# TODO - Get a function which does not exhaust the OSes entropy pool.
	return os.urandom(size)
