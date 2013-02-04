#!/usr/bin/python
# -*- coding: utf-8 -*-

from Crypto.Hash import HMAC
from Crypto.Hash import SHA256

import obfsproxy.transports.base as base

import math


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
			raise ValueError("The PRK must be at least %d bytes in length." % \
					self.HashLen)

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
			tmp = HMAC.new(self.prk, tmp + self.info + chr(self.ctr),
					SHA256).digest()
			self.T += tmp
			self.ctr += 1

		return self.T[:self.length]
