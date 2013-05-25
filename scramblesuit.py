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
import random
import string
import time
import argparse

import probdist
import mycrypto
import message
import const
import util
import packetmorpher
import processprotocol
import ticket


log = logging.get_obfslogger()


class ScrambleSuitTransport( base.BaseTransport ):

	def __init__( self ):

		log.info("Initializing %s." % const.TRANSPORT_NAME)

		# Initialize the protocol's state machine.
		log.debug("Switching to state ST_WAIT_FOR_AUTH.")
		self.state = const.ST_WAIT_FOR_AUTH

		# UniformDH object.
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

		# Shared secret k_B which is only used for UniformDH.
		if not hasattr(self, 'uniformDHSecret'):
			self.uniformDHSecret = None
		if self.uniformDHSecret:
			log.info("UniformDH shared secret: %s." % self.uniformDHSecret)

		# Path to a file which contains a master key and the according ticket.
		if not hasattr(self, "ticketFile"):
			self.ticketFile = None
		if self.ticketFile:
			log.info("Using session ticket file `%s'." % self.ticketFile)
			const.TICKET_FILE = self.ticketFile

		# Used by the unpack mechanism
		self.totalLen = None
		self.payloadLen = None
		self.flags = None


	def _deriveSecrets( self, masterKey ):
		"""Derives session keys (AES keys, counter nonces and HMAC keys) from
		the given master key.  All key material is derived using
		HKDF-SHA256."""

		log.debug("Deriving session keys from master key 0x%s..." % \
				masterKey.encode('hex')[:10])

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
		"""This method is called by obfsproxy when the TCP connection to the
		remote end was destroyed; either cleanly or in a non-clean fashion."""

		# This is only printed because the user might be interested in it.
		if reason and reason.check(error.ConnectionLost):
			log.info("The connection was lost in a non-clean fashion.")


	def handshake( self, circuit ):
		"""This function is invoked after a circuit was established.  If a
		ticket is available, the client redeems it.  Otherwise, the client
		tries to start a UniformDH handshake."""

		if self.weAreClient:
			if (not self.uniformDHSecret) and (not self.ticketFile):
				raise base.PluggableTransportError("Neither a UniformDH " \
						"secret nor a ticket is available.  ScrambleSuite " \
						"needs at least one of these two for authentication.")

		# Send a session ticket to the server (if we have one).
		if self.weAreClient and os.path.exists(const.TICKET_FILE):

			blob = util.readFromFile(const.TICKET_FILE, \
					const.MASTER_KEY_LENGTH + const.TICKET_LENGTH)

			masterKey = blob[:const.MASTER_KEY_LENGTH]
			ticket = blob[const.MASTER_KEY_LENGTH: \
					const.MASTER_KEY_LENGTH + const.TICKET_LENGTH]

			log.debug("Redeeming session ticket 0x%s..." % \
					ticket.encode('hex')[:10])
			self._deriveSecrets(masterKey)
			padding = mycrypto.weak_random(random.randint(0, \
					const.MAX_PADDING_LENGTH))

			key = "A" * 32
			magic = mycrypto.HMAC_SHA256_128(key, key + ticket)
			mac = mycrypto.HMAC_SHA256_128(key, ticket + padding + magic + \
					self._epoch())

			circuit.downstream.write(ticket + padding + magic + mac)
			self.redeemedTicket = True

			# TODO - The client can't know at this point whether the server
			# accepted the ticket.
			log.debug("Switching to state ST_CONNECTED.")
			self.state = const.ST_CONNECTED

		# Conduct an authenticated UniformDH handshake if there's no ticket.
		elif self.weAreClient:
			log.debug("No session ticket to redeem.  Running UniformDH.")

			# TODO - use packet morpher for handshake.
			circuit.downstream.write(self.__createUniformDHPK())


	def sendRemote( self, circuit, data ):
		"""Encrypt, then chop the given data into pieces and send it to the
		remote end."""

		if (data is None) or (len(data) == 0):
			return

		log.info("Processing %d bytes of outgoing data." % len(data))

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
				self.flags = ord(aes.decrypt(self.recvBuf[20]))

				# Abort immediately if the extracted lengths do not make sense.
				if not message.saneHeader(self.totalLen, self.payloadLen, \
						self.flags):
					raise base.PluggableTransportError("Invalid header: " \
							"totalLen=%d, payloadLen=%d. flags=%d" % \
							(self.totalLen, self.payloadLen, self.flags))
				log.debug("Message header: totalLen=%d, payloadLen=%d, flags" \
						"=%d" % (self.totalLen, self.payloadLen, self.flags))

			if (len(self.recvBuf) - const.HDR_LENGTH) < self.totalLen:
				return fwdBuf

			# We have a full message; let's extract it.
			else:
				rcvdHMAC = self.recvBuf[0:const.HMAC_LENGTH]
				vrfyHMAC = mycrypto.HMAC_SHA256_128(self.recvHMAC, \
						self.recvBuf[const.HMAC_LENGTH:(self.totalLen + \
						const.HDR_LENGTH)])

				# Abort immediately if the HMAC is invalid.
				if rcvdHMAC != vrfyHMAC:
					raise base.PluggableTransportError("Invalid HMAC!")

				fwdBuf += aes.decrypt(self.recvBuf[const.HDR_LENGTH: \
						(self.totalLen+const.HDR_LENGTH)])[:self.payloadLen]
				self.recvBuf = self.recvBuf[const.HDR_LENGTH + self.totalLen:]

				# Store tickets instead of handing them to the application.
				if self.flags == const.FLAG_NEW_TICKET:
					self._storeNewTicket(fwdBuf[0:const.MASTER_KEY_LENGTH], \
							fwdBuf[const.MASTER_KEY_LENGTH: \
							const.MASTER_KEY_LENGTH + const.TICKET_LENGTH])
					self.totalLen = self.payloadLen = self.flags = None
					return None

				# Protocol message extracted - resetting length fields.
				self.totalLen = self.payloadLen = self.flags = None

		log.debug("Unpacked %d bytes of data: 0x%s..." % \
				(len(fwdBuf), fwdBuf[:10].encode('hex')))
		return fwdBuf


	def sendLocal( self, circuit, data ):
		"""Deobfuscate, then decrypt the given data and send it to the local
		Tor client."""

		# Don't send empty data.
		if len(data) == 0 or not data:
			return

		log.info("Processing %d bytes of incoming data." % len(data))

		finalData = self.unpack(data, self.recvCrypter)
		if finalData is not None:
			# Send encrypted and obfuscated data.
			circuit.upstream.write(finalData)


	def _epoch( self ):
		"""Return a coarse-grained Unix time stamp which is divided by
		EPOCH_GRANULARITY."""

		return str(int(time.time()) / const.EPOCH_GRANULARITY)


	def _flushSendBuffer( self, circuit ):
		"""Flushes the send buffer which could have been filled by the
		application while ScrambleSuit was still busy handling
		authentication."""

		# FIXME - this method is not called anywhere.

		# Flush the buffered data, the application wanted to send before.
		if len(self.sendBuf):
			log.debug("Flushing %d bytes of buffered data from local Tor." % \
				len(self.sendBuf))
			self.sendRemote(circuit, self.sendBuf)
			self.sendBuf = ""


	def _receiveTicket( self, data ):
		"""Verify and extract ticket handshake message."""

		if len(data) < (const.TICKET_LENGTH + const.MAGIC_LENGTH + \
				const.HMAC_LENGTH):
			return False

		potentialTicket = data.peek()
		key = "A" * 32

		# Look for the magic value to easily locate the HMAC.
		magic = mycrypto.HMAC_SHA256_128(key, key + \
				potentialTicket[:const.TICKET_LENGTH])
		index = potentialTicket.find(magic)
		if (index < 0) or ((len(potentialTicket) - index - \
				const.MAGIC_LENGTH) < const.HMAC_LENGTH):
			log.debug("Could not find magic value for ticket yet.")
			return False

		# Verify HMAC before touching the icky data.
		existingMAC = potentialTicket[index + const.MAGIC_LENGTH:index +
				const.MAGIC_LENGTH + const.HMAC_LENGTH]
		newMAC = mycrypto.HMAC_SHA256_128(key, \
				potentialTicket[0:index + const.MAGIC_LENGTH] + self._epoch())

		if newMAC == existingMAC:
			log.debug("HMAC of session ticket is valid.")
			data.drain()
		else:
			log.error("Invalid HMAC despite valid magic value.")
			return False

		# Now try to decrypt and parse ticket.
		log.debug("Attempting to decrypt potential session ticket.")
		newTicket = ticket.decryptTicket(potentialTicket[:const.TICKET_LENGTH])

		if ticket != None and newTicket.isValid():
			log.debug("The ticket is valid.  Now deriving keys.")
			data.drain(const.TICKET_LENGTH)
			self._deriveSecrets(newTicket.masterKey)
			log.debug("Switching to state ST_CONNECTED.")
			self.state = const.ST_CONNECTED
			return True
		else:
			return False


	def _storeNewTicket( self, masterKey, ticket ):
		"""Store a new session ticket and the according master key for future
		use."""

		assert len(masterKey) == const.MASTER_KEY_LENGTH
		assert len(ticket) == const.TICKET_LENGTH

		log.debug("Storing newly received session ticket.")

		util.writeToFile(masterKey + ticket, const.TICKET_FILE)


	def _receiveClientsUniformDHPK( self, data, circuit ):

		clientPK = self.__receiveUniformDHPK(data)
		if not clientPK:
			return

		self.dh = obfs3_dh.UniformDH()
		try:
			masterKey = self.dh.get_secret(clientPK)
		except ValueError:
			raise base.PluggableTransportError("Corrupted public key.")

		self._deriveSecrets(masterKey)

		log.debug("Switching to state ST_CONNECTED.")
		self.state = const.ST_CONNECTED

		# Now send our PK to the client so it can finish the handshake as well.
		myPK = self.dh.get_public()
		assert myPK

		ticket, masterKey = self._getSessionTicket()

		ticketMsg = message.ProtocolMessage(payload=masterKey + ticket, \
				flags=const.FLAG_NEW_TICKET)
		ticketMsg = ticketMsg.encryptAndHMAC(self.sendCrypter, \
				self.sendHMAC)

		handshakeMsg = self.__createUniformDHPK(myPK)

		log.debug("Sending %d bytes of UniformDH handshake and ticket." %
				len(handshakeMsg + ticketMsg))
		circuit.downstream.write(handshakeMsg + ticketMsg)
		# TODO - use sendRemote() to send ticketMsg

		return True


	def _receiveServersUniformDHPK( self, data ):

		serverPK = self.__receiveUniformDHPK(data)
		if not serverPK:
			return

		log.debug("Received UniformDH public key.  Now deriving session keys.")

		try:
			masterKey = self.dh.get_secret(serverPK)
		except ValueError:
			raise base.PluggableTransportError("Corrupted public key.")

		self._deriveSecrets(masterKey)

		log.debug("Switching to state ST_CONNECTED.")
		self.state = const.ST_CONNECTED

		return True


	def __receiveUniformDHPK( self, data ):

		assert self.uniformDHSecret is not None

		# Do we already have the minimum amount of data?
		if len(data) < (const.PUBLIC_KEY_LENGTH + const.MAGIC_LENGTH + \
				const.HMAC_LENGTH):
			return False

		handshake = data.peek()

		# Look for the magic value to easily locate the HMAC.
		magic = mycrypto.HMAC_SHA256_128(self.uniformDHSecret, \
				self.uniformDHSecret + handshake[:const.PUBLIC_KEY_LENGTH])
		index = handshake.find(magic)
		if (index < 0) or ((len(handshake) - index - \
				const.MAGIC_LENGTH) < const.HMAC_LENGTH):
			log.debug("Could not find magic value for UniformDH yet.")
			return False

		# Verify HMAC before touching the icky data.
		existingMAC = handshake[index + const.MAGIC_LENGTH : index +
				const.MAGIC_LENGTH + const.HMAC_LENGTH]
		newMAC = mycrypto.HMAC_SHA256_128(self.uniformDHSecret, \
				handshake[0 : index + const.MAGIC_LENGTH] + self._epoch())

		if newMAC == existingMAC:
			log.debug("HMAC of UniformDH public key is valid.")
			data.drain(index + const.MAGIC_LENGTH + const.HMAC_LENGTH)
		else:
			log.error("Invalid HMAC despite valid magic value.")
			return False

		return handshake[:const.PUBLIC_KEY_LENGTH]


	# TODO - bad method name
	def __createUniformDHPK( self, publicKey=None ):

		assert self.uniformDHSecret is not None

		if not publicKey:
			self.dh = obfs3_dh.UniformDH()
			publicKey = self.dh.get_public()
		padding = mycrypto.weak_random(random.randint(0, 123)) # TODO

		# Generate magic value to make it easier to locate the HMAC.
		magic = mycrypto.HMAC_SHA256_128(self.uniformDHSecret, \
				self.uniformDHSecret + publicKey)

		# Authenticate the handshake including the current approximate epoch.
		mac = mycrypto.HMAC_SHA256_128(self.uniformDHSecret, publicKey + \
				padding + magic + self._epoch())

		return publicKey + padding + magic + mac


	def receivedDownstream( self, data, circuit ):
		"""Data coming from the remote end point and going to the local Tor."""

		if self.weAreServer and (self.state == const.ST_WAIT_FOR_AUTH):

			# First, try to interpret the incoming data as session ticket.
			if self._receiveTicket(data):
				log.debug("Ticket authentication succeeded.")

			# Second, interpret the data as a UniformDH handshake.
			elif self._receiveClientsUniformDHPK(data, circuit):
				log.debug("UniformDH authentication succeeded.")

			else:
				log.debug("Authentication unsuccessful so far.  " \
						"Waiting for more data.")
				return

		if self.weAreClient and (self.state == const.ST_WAIT_FOR_AUTH):

			if not self._receiveServersUniformDHPK(data):
				log.debug("Unable to read UniformDH public key at this point.")
				return

		if self.state == const.ST_CONNECTED:
			self.sendLocal(circuit, data.read())


	def _getSessionTicket( self ):

		log.debug("Generating new session ticket and master key.")
		masterKey = mycrypto.strong_random(const.MASTER_KEY_LENGTH)

		newTicket = ticket.new(masterKey)
		rawTicket = newTicket.issue()

		return rawTicket, masterKey


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


	@classmethod
	def register_external_mode_cli( cls, subparser ):
		"""Register a ScrambleSuit-specific command line argument for obfsproxy
		which can be used to pass the UniformDH shared secret to
		ScrambleSuit."""

		subparser.add_argument('--shared-secret', type=str, \
				help='Shared secret for UniformDH', dest="uniformDHSecret")

		subparser.add_argument('--ticket-file', type=str, help='Path to a ' \
				'session ticket (only for client)', dest="ticketFile")

		super(ScrambleSuitTransport, cls).register_external_mode_cli(subparser)


	@classmethod
	def validate_external_mode_cli(cls, args):

		if args.uniformDHSecret:
			cls.uniformDHSecret = args.uniformDHSecret

		if args.ticketFile:
			cls.ticketFile = args.ticketFile

		if args.uniformDHSecret and len(args.uniformDHSecret) != \
				const.SHARED_SECRET_LENGTH:
			raise base.PluggableTransportError("The UniformDH shared secret " \
					"must be %d bytes in length but %d bytes given." % \
					(const.SHARED_SECRET_LENGTH, len(args.uniformDHSecret)))

		super(ScrambleSuitTransport, cls).validate_external_mode_cli(args)


	def handle_socks_args( self, args ):
		"""This method is called with arguments which are received over the
		SOCKS handshake.  That way, the UniformDH shared secret can reach
		ScrambleSuit over SOCKS."""

		log.debug("Received the following arguments over SOCKS: %s." % args)

		# A shared secret might already be set if obfsproxy is in
		# external mode.
		if self.uniformDHSecret:
			log.info("A UniformDH shared secret was already specified over" \
					"the command line.  Using the SOCKS secret.")

		if len(args) != 1:
			raise base.SOCKSArgsError("Too many SOCKS arguments " \
					"(expected 1 but got %d)." % len(args))

		if not args[0].startswith("shared-secret="):
			raise base.SOCKSArgsError("The SOCKS argument should start with" \
					"`shared-secret='.")

		self.uniformDHSecret = args[0][14:]

		if len(args.uniformDHSecret) != const.SHARED_SECRET_LENGTH:
			raise base.PluggableTransportError("The UniformDH shared secret " \
					"must be %d bytes in length but %d bytes given." % \
					(const.SHARED_SECRET_LENGTH, len(args.uniformDHSecret)))


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
