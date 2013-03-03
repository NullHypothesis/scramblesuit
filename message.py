#!/usr/bin/env python
# -*- coding: utf-8 -*-

import obfsproxy.common.log as logging
import obfsproxy.common.serialize as serialize

import struct
import mycrypto
import const

log = logging.get_obfslogger()


def createMessages( data ):

	messages = []

	log.debug("Creating protocol messages.")

	while len(data) >= (const.MTU - const.HDR_LENGTH):
		messages.append(ProtocolMessage(data[:(const.MTU - const.HDR_LENGTH)]))
		data = data[(const.MTU - const.HDR_LENGTH):]

	messages.append(ProtocolMessage(data))

	return messages



class ProtocolMessage( object ):
	"""Provides an abstraction of ScrambleSuit protocol messages. The class
	provides methods to build, encrypt and pad protocol messages."""

	def __init__( self, payload="", paddingLen=0 ):

		payloadLen = len(payload)
		assert((payloadLen + paddingLen) <= (const.MTU - const.HDR_LENGTH))

		self.hmac = ""
		self.totalLen = payloadLen + paddingLen
		self.payloadLen = payloadLen
		self.payload = payload


	def encryptAndHMAC( self, crypter, HMACKey ):

		encrypted = crypter.encrypt(serialize.htons(self.totalLen) + \
				serialize.htons(self.payloadLen) + self.payload + \
				(self.totalLen - self.payloadLen) * '\0')

		hmac = mycrypto.MyHMAC_SHA256_128(HMACKey, encrypted)

		return hmac + encrypted


	def addPadding( self, paddingLen ):

		# The padding must not exceed the message size.
		assert ((self.totalLen + paddingLen) <= (const.MTU - const.HDR_LENGTH))

		if paddingLen == 0:
			return

		log.debug("Adding %d bytes of padding to %d-byte message." % \
				(paddingLen, const.HDR_LENGTH + self.totalLen))
		self.totalLen += paddingLen


	def __len__( self ):
		return const.HDR_LENGTH + self.totalLen
