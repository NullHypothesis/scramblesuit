#!/usr/bin/env python
# -*- coding: utf-8 -*-

MTU = 1448
HDR_LENGTH = 20

import obfsproxy.common.log as logging

import struct
import mycrypto

log = logging.get_obfslogger()

def ntohs( data ):
	return struct.unpack('!H', data)


def htons( data ):
	return struct.pack('!H', data)

# +-----------------+--------------+----------------+---------+---------+
# |     16-byte     |    2-byte    |     2-byte     |         |         |
# | HMAC-SHA256-128 | total length | payload length | payload | padding |
# +-----------------+--------------+----------------+---------+---------+

def createMessages( data ):

	messages = []

	log.debug("Creating protocol messages.")

	while len(data) >= (MTU - HDR_LENGTH):
		messages.append(ProtocolMessage(data[:(MTU - HDR_LENGTH)]))
		data = data[(MTU - HDR_LENGTH):]

	messages.append(ProtocolMessage(data))

	return messages



class ProtocolMessage( object ):
	"""Provides an abstraction of ScrambleSuit protocol messages. The class
	provides methods to build, encrypt and pad protocol messages."""

	def __init__( self, payload="", paddingLen=0 ):

		payloadLen = len(payload)
		assert((payloadLen + paddingLen) <= (MTU - HDR_LENGTH))

		self.hmac = ""
		self.totalLen = payloadLen + paddingLen
		self.payloadLen = payloadLen
		self.payload = payload


	def encryptAndHMAC( self, crypter, HMACKey ):

		log.debug("Encrypting message body.")
		encrypted = crypter.encrypt(htons(self.totalLen) + \
				htons(self.payloadLen) + self.payload + \
				(self.totalLen - self.payloadLen) * '\0')

		log.debug("Building HMAC over encrypted body.")
		hmac = mycrypto.MyHMAC_SHA256_128(HMACKey, encrypted)

		return hmac + encrypted


	def addPadding( self, paddingLen ):

		if paddingLen == 0:
			return

		if (self.totalLen + paddingLen) > (MTU - HDR_LENGTH):
			log.error("Padding would exceed MTU.")
			# TODO - raise exception

		log.debug("Adding %d bytes of padding to %d-byte message." % \
				(paddingLen, HDR_LENGTH + self.totalLen))
		self.totalLen += paddingLen


	def __len__( self ):
		return HDR_LENGTH + self.totalLen



def decryptAndVerify( encryptedMsg, crypter, HMACKey ):

	assert(HDR_LENGTH <= len(encryptedMsg) <= MTU)
	assert(crypter and HMACKey)

	hmac = mycrypto.MyHMAC_SHA256_128(HMACKey, encryptedMsg)
	if hmac != encryptedMsg[:16]:
		log.debug("hmac check failed.")
