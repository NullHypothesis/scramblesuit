#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
The scramblesuit module implements the ScrambleSuit obfuscation protocol.
For more details, check out http://www.cs.kau.se/philwint/scramblesuit/
"""

from twisted.internet import error
from twisted.internet import reactor

import obfsproxy.transports.base as base
import obfsproxy.common.serialize as pack
import obfsproxy.common.log as logging
import obfsproxy.transports.obfs3_dh as obfs3_dh

import os
import sys
import random
import struct
import string
import time

import probdist
import timelock
import mycrypto
import message
import const
import util
import packetmorpher
import processprotocol
import sessionticket


log = logging.get_obfslogger()


class ScrambleSuitTransport( base.BaseTransport ):

	def __init__( self ):

		log.info("Initializing %s." % const.TRANSPORT_NAME)

		# Initialize the protocol's state machine.
		log.debug("Switching to state ST_WAIT_FOR_AUTH.")
		self.state = const.ST_WAIT_FOR_AUTH

		self.dh = None

		# Buffers for incoming and outgoing data.
		self.sendBuf = self.recvBuf = ""

		# Caches the outgoing data before written to the wire.
		self.choppedPieces = []

		# AES instances for incoming and outgoing data.
		self.sendCrypter = mycrypto.PayloadCrypter()
		self.recvCrypter = mycrypto.PayloadCrypter()

		# Packet morpher to modify the protocol's packet length distribution.
		self.pktMorpher =  packetmorpher.PacketMorpher()

		# Inter arrival time morpher to obfuscate inter arrival times.
		self.iatMorpher = probdist.RandProbDist(lambda: random.random() % 0.01)

		# `True' if the client used a session ticket, `False' otherwise.
		self.redeemedTicket = None

		# Used by the unpack mechanism
		self.totalLen = None
		self.payloadLen = None
		self.flags = None


	def _deriveSecrets( self, masterKey ):
		"""Derives session keys (AES keys, counter nonces, HMAC keys and magic
		values) from the given master secret. All key material is derived using
		HKDF-SHA256."""

		log.debug("Master key: 0x%s." % masterKey.encode('hex'))

		# We need key material for two magic values, symmetric keys, nonces and
		# HMACs. All of them are 32 bytes in size.
		hkdf = mycrypto.HKDF_SHA256(masterKey, "", 32 * 8)
		okm = hkdf.expand()

		# Set the symmetric AES keys.
		self.sendCrypter.setSessionKey(okm[0:32],  okm[32:64])
		self.recvCrypter.setSessionKey(okm[64:96], okm[96:128])

		# Set the HMAC keys.
		self.sendHMAC = okm[128:160]
		self.recvHMAC = okm[160:192]

		if self.weAreServer:
			self.sendHMAC, self.recvHMAC = util.swap(self.sendHMAC, self.recvHMAC)
			self.sendCrypter, self.recvCrypter = util.swap(self.sendCrypter, \
					self.recvCrypter)


	def circuitDestroyed( self, circuit, reason, side ):

		if reason == None or side == None:
			log.debug("No reason given why circuit died.")
			return

		# reason is an instance of twisted.python.failure.Failure
		log.debug("Circuit on %s side died because of: %s" % \
			(side, reason.getErrorMessage()))
		log.debug("Responsible value: %s." % type(reason.value))
		log.debug("Responsible type: %s." % str(reason.type))

		# For established TCP connections, twisted only tells us whether it was
		# closed in a clean or non-clean way. We could use our protocol state
		# machine to get some idea whether this is due to networking or
		# censorship effects.
		if reason.check(error.ConnectionLost):
			log.debug("The connection was lost due to a blacklisted error!")


	def handshake( self, circuit ):
		"""This function is invoked after a circuit was established. The server
		generates a time-lock puzzle and sends it to the client. The client
		does nothing during the handshake."""

		# Send a session ticket to the server (if we have one).
		if self.weAreClient and os.path.exists(const.DATA_DIRECTORY + \
				const.TICKET_FILE):

			try:
				with open(const.DATA_DIRECTORY + const.TICKET_FILE, "rb") as fd:
					masterKey = fd.read(const.MASTER_KEY_SIZE)
					ticket = fd.read(const.TICKET_LENGTH)
					fd.close()

			except IOError as e:
				log.error("Could not read session ticket from \"%s\"." % \
						(const.DATA_DIRECTORY + const.TICKET_FILE))

			log.debug("Trying to redeem session ticket: 0x%s..." % \
					ticket.encode('hex')[:10])
			self._deriveSecrets(masterKey)
			padding = mycrypto.weak_random(random.randint(0, \
					const.MAX_PADDING_LENGTH))
			circuit.downstream.write(ticket + padding)
			self.redeemedTicket = True

		# Conduct an authenticated UniformDH handshake.
		elif self.weAreClient:
			log.debug("No session ticket to redeem.  Running UniformDH.")
			self._sendUniformDHPK(circuit)


	def sendSessionTicket( self, circuit, ticket ):

		padding = mycryto.weak_random(random.randint(0, \
				const.MAX_PADDING_LENGTH))

		vrfyHMAC = mycrypto.MyHMAC_SHA256_128(self.recvHMAC, \
				self.recvBuf[const.HMAC_LENGTH:(self.totalLen + \
				const.HDR_LENGTH)])

		hmacInput = ticket, padding, epoch
		hmac = mycrypto.MyHMAC_SHA256_128(self.sendHMAC, hmacInput)




	def sendRemote( self, circuit, data ):
		"""Encrypt, then obfuscate the given data and send it to the remote
		bridge."""

		if (data is None) or (len(data) == 0):
			return

		# Wrap the application's data in ScrambleSuit protocol messages.
		messages = message.createDataMessages(data)

		# Invoke the packet morpher and pad the last protocol message.
		chopper, paddingLen = self.pktMorpher.morph(sum([len(msg) \
				for msg in messages]))

		if paddingLen > const.HDR_LENGTH:
			messages.append(message.ProtocolMessage("", \
					paddingLen=paddingLen - const.HDR_LENGTH))

		# Encrypt and authenticate all messages.
		blurb = string.join([msg.encryptAndHMAC(self.sendCrypter, self.sendHMAC) \
				for msg in messages], '')

		# Chop the encrypted blurb to fit the target probability distribution.
		self.choppedPieces += chopper(blurb)
		self.__flushPieces(circuit)


	def __flushPieces( self, circuit ):
		"""Writes the cached and chopped data pieces to the wire using
		`circuit'. After every write, control is given back to the reactor so
		it has a chance to actually write the data. Shortly thereafter, this
		function is called again if data is left to write."""

		assert circuit

		if len(self.choppedPieces) == 0:
			return

		if len(self.choppedPieces[0]) > 0:
			log.debug("Writing %d bytes of data to downstream." % \
					len(self.choppedPieces[0]))
			circuit.downstream.write(self.choppedPieces[0])

		if len(self.choppedPieces) > 1:
			self.choppedPieces = self.choppedPieces[1:]
			reactor.callLater(self.iatMorpher.randomSample(), \
				self.__flushPieces, circuit)


	def unpack( self, data, aes ):

		# Input buffer which is not yet processed and forwarded.
		self.recvBuf += data
		fwdBuf = ""

		# Keep trying to unpack as long as there seems to be enough data.
		while len(self.recvBuf) >= const.HDR_LENGTH:

			# Extract length fields if we don't have them already.
			if self.totalLen == None:
				self.totalLen = pack.ntohs(aes.decrypt(self.recvBuf[16:18]))
				self.payloadLen = pack.ntohs(aes.decrypt(self.recvBuf[18:20]))
				self.flags = aes.decrypt(self.recvBuf[20])

				# Abort immediately if the extracted lengths do not make sense.
				if not message.saneHeader(self.totalLen, self.payloadLen, \
						self.flags):
					raise base.PluggableTransportError("Invalid header: " \
							"totalLen=%d, payloadLen=%d. flags=%d" % \
							(self.totalLen, self.payloadLen, ord(self.flags)))
				log.debug("Message header: totalLen=%d, payloadLen=%d, flags" \
						"=%d" % (self.totalLen, self.payloadLen, ord(self.flags)))

			if (len(self.recvBuf) - const.HDR_LENGTH) < self.totalLen:
				return fwdBuf

			# We have a full message; let's extract it.
			else:
				log.debug("Extracting message of type %d." % ord(self.flags))
				rcvdHMAC = self.recvBuf[0:const.HMAC_LENGTH]
				vrfyHMAC = mycrypto.MyHMAC_SHA256_128(self.recvHMAC, \
						self.recvBuf[const.HMAC_LENGTH:(self.totalLen + \
						const.HDR_LENGTH)])

				# Abort immediately if the HMAC is invalid.
				if rcvdHMAC != vrfyHMAC:
					raise base.PluggableTransportError("Invalid HMAC!")

				fwdBuf += aes.decrypt(self.recvBuf[const.HDR_LENGTH: \
						(self.totalLen+const.HDR_LENGTH)])[:self.payloadLen]

				# check type here and do according stuff.

				self.recvBuf = self.recvBuf[const.HDR_LENGTH + self.totalLen:]
				# Protocol message extracted - resetting length fields.
				self.totalLen = self.payloadLen = self.flags = None

		log.debug("Unpacked %d bytes of data: 0x%s..." % \
				(len(fwdBuf), fwdBuf[:10].encode('hex')))
		return fwdBuf


	def getNewTicket( self, ticket ):

		assert len(ticket) == const.TICKET_LENGTH


	def sendLocal( self, circuit, data ):
		"""Deobfuscate, then decrypt the given data and send it to the local
		Tor client."""

		# Don't send empty data.
		if len(data) == 0 or not data:
			return

		log.debug("Processing %d bytes of incoming data." % len(data))

		# Send encrypted and obfuscated data.
		circuit.upstream.write(self.unpack(data, self.recvCrypter))


	def _epoch( self ):
		return str(int(time.time()) / const.EPOCH_GRANULARITY)

	def _receiveEncryptedTicket( self, data ):

		expected = const.TICKET_LENGTH + const.MASTER_KEY_SIZE

		assert len(data) >= expected
		data = data.read(expected)

		#decrypted = self.recvCrypter.decrypt(data[:expected])
		ticket = decrypted[:const.TICKET_LENGTH]
		nextMasterKey = decrypted[const.TICKET_LENGTH : expected]

		util.writeToFile(nextMasterKey + ticket, \
				const.DATA_DIRECTORY + const.TICKET_FILE)


	def _flushSendBuffer( self, circuit ):

		# Flush the buffered data, Tor wanted to send in the meantime.
		if len(self.sendBuf):
			log.debug("Flushing %d bytes of buffered data from local Tor." % \
				len(self.sendBuf))
			self.sendRemote(circuit, self.sendBuf)
			self.sendBuf = ""
		else:
			log.debug("Empty buffer: no data to flush.")


	def _receiveTicket( self, data ):

		if len(data) < (const.TICKET_LENGTH + const.HMAC_LENGTH):
			return False

		# Verify HMAC before touching the icky data.
		potentialTicket = data.peek()
		key = "A" * 32
		mac = mycrypto.MyHMAC_SHA256_128(key, \
				potentialTicket[:-const.HMAC_LENGTH] + self._epoch())
		if mac == potentialTicket[-const.HMAC_LENGTH:]:
			log.debug("HMAC of session ticket is valid.")
			data.drain()
		else:
			return False

		# Now try to decrypt and parse ticket.
		log.debug("Attempting to decrypt potential session ticket.")
		ticket = sessionticket.decryptTicket(potentialTicket[:const.TICKET_LENGTH])

		if ticket != None and ticket.isValid():
			log.debug("The ticket is valid.  Now deriving keys.")
			data.drain(const.TICKET_LENGTH)
			self._deriveSecrets(ticket.masterKey)
		else:
			return False


	def _receiveUniformDHPK( self, data ):

		if len(data) < (const.PUBLIC_KEY_LENGTH + const.HMAC_LENGTH):
			return False

		# Verify HMAC before touching the icky data.
		handshake = data.peek()
		key = "U" * 32
		mac = mycrypto.MyHMAC_SHA256_128(key, \
				handshake[:-const.HMAC_LENGTH] + self._epoch())
		if mac == handshake[-const.HMAC_LENGTH:]:
			log.debug("HMAC of UniformDH public key is valid.")
			data.drain()
		else:
			return False

		# Now try to finish UniformDH handshake.
		otherPK = handshake[:const.PUBLIC_KEY_LENGTH]
		log.debug("Received UniformDH public key.  Now deriving session keys.")

		if self.weAreServer:
			self.dh = obfs3_dh.UniformDH()

		try:
			masterKey = self.dh.get_secret(otherPK)
		except ValueError:
			raise base.PluggableTransportError("Corrupted public key.")

		self._deriveSecrets(masterKey)

		return self.dh.get_public()


	def _sendUniformDHPK( self, circuit, publicKey=None ):

		# TODO - where does key come from?
		key = "U" * 32

		log.debug("Sending UniformDH public key.")

		if not publicKey:
			self.dh = obfs3_dh.UniformDH()
			publicKey = self.dh.get_public()
		padding = mycrypto.weak_random(random.randint(0, 123)) # TODO

		# Authenticate the handshake including the current approximate epoch.
		mac = mycrypto.MyHMAC_SHA256_128(key, publicKey + padding + \
				self._epoch())

		# TODO - use packet morpher for handshake.
		circuit.downstream.write(publicKey + padding + mac)



	def receivedDownstream( self, data, circuit ):
		"""Data coming from the remote end point and going to the local Tor."""

		if self.weAreServer and self.state == const.ST_WAIT_FOR_AUTH:
			if not self._receiveTicket(data):
				log.debug("Unable to read session ticket at this point.")

			publicKey = self._receiveUniformDHPK(data)
			if publicKey == False:
				log.debug("Unable to read UniformDH public key at this point.")
				return
			else:
				self._sendUniformDHPK(circuit, publicKey)

			log.debug("Switching to state ST_CONNECTED.")
			self.state = const.ST_CONNECTED

		if self.weAreClient and self.state == const.ST_WAIT_FOR_AUTH:
			if not self._receiveUniformDHPK(data):
				log.debug("Unable to read UniformDH public key at this point.")
				return

			log.debug("Switching to state ST_CONNECTED.")
			self.state = const.ST_CONNECTED

		if self.state == const.ST_CONNECTED:
			self.sendLocal(circuit, data.read())


	def _getSessionTicket( self, circuit ):

		log.debug("Generating new session ticket and master key.")
		nextMasterKey = mycrypto.strong_random(const.MASTER_KEY_SIZE)

		ticket = sessionticket.new(nextMasterKey)
		rawTicket = ticket.issue()

		return rawTicket, nextMasterKey


	def receivedUpstream( self, data, circuit ):
		"""Data coming from the local Tor client and going to the remote
		bridge. If the data can't be sent immediately (in state ST_CONNECTED)
		it is buffered to be transmitted later."""

		if self.state == const.ST_CONNECTED:
			self.sendRemote(circuit, data.read())

		# Buffer data we are not ready to transmit yet. It will get flushed
		# once the puzzle is solved and the connection established.
		else:
			self.sendBuf += data.read()
			log.debug("%d bytes of outgoing data buffered." % len(self.sendBuf))


class ScrambleSuitClient( ScrambleSuitTransport ):

	def __init__( self ):
		self.weAreClient = True
		self.weAreServer = False
		ScrambleSuitTransport.__init__(self)


class ScrambleSuitServer( ScrambleSuitTransport ):

	def __init__( self ):
		self.weAreServer = True
		self.weAreClient = False
		ScrambleSuitTransport.__init__(self)
