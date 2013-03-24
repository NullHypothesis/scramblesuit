#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
The scramblesuit module implements the ScrambleSuit obfuscation protocol.
For more details, check out http://www.cs.kau.se/philwint/scramblesuit/
"""

from twisted.internet import error
from twisted.internet import reactor
from twisted.application.internet import TimerService

import obfsproxy.transports.base as base
import obfsproxy.common.serialize as pack
import obfsproxy.common.log as logging

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


class ScrambleSuitDaemon( base.BaseTransport ):

	def __init__( self ):

		log.info("Initializing %s." % const.TRANSPORT_NAME)

		# Initialize the protocol's state machine.
		if self.weAreServer:
			log.debug("Switching to state ST_WAIT_FOR_TICKET.")
			self.state = const.ST_WAIT_FOR_TICKET
		elif self.weAreClient:
			log.debug("Switching to state ST_WAIT_FOR_PUZZLE.")
			self.state = const.ST_WAIT_FOR_PUZZLE

		# Magic values to tell when the actual communication begins.
		self.sendMagic = self.recvMagic = None

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

		# Circuit to write data to and receive data from.
		self.circuit = None

		# Timer service to generate garbage data while puzzle is being solved.
		self.ts = None

		# When the client magic was sent to guess if the ticket was accepted.
		self.magicSent = None

		# `True' if the client used a session ticket, `False' otherwise.
		self.redeemedTicket = None

		# Cache the puzzle if the session ticket is not accepted by the server.
		self.cachedPuzzle = None

		# Used by the unpack mechanism
		self.totalLen = None
		self.payloadLen = None


	def generateNoise( self ):
		"""Send random noise to the remote end point to confuse statistical
		classifiers. The remote machine will simply discard the data."""

		# FIXME - use packet morpher oracle to determine sizes.
		noise = mycrypto.weak_random(random.randint(0, 1000))
		log.debug("Generated %d bytes of noise. Sending now." % len(noise))
		assert self.circuit
		self.circuit.downstream.write(noise)


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

		# Derive a magic value for the client as well as the server. They must
		# be distinct to prevent fingerprinting (e.g. look for two identical
		# 256-bit strings).
		self.sendMagic = okm[128:160]
		self.recvMagic = okm[160:192]

		# Set the HMAC keys.
		self.sendHMAC = okm[192:224]
		self.recvHMAC = okm[224:256]

		if self.weAreServer:
			self.sendHMAC, self.recvHMAC = util.swap(self.sendHMAC, self.recvHMAC)
			self.sendCrypter, self.recvCrypter = util.swap(self.sendCrypter, \
					self.recvCrypter)
			self.sendMagic, self.recvMagic = util.swap(self.sendMagic, \
					self.recvMagic)

		log.debug("Magic values derived from session key: send=0x%s, " \
			"recv=0x%s." % (self.sendMagic.encode('hex'), \
			self.recvMagic.encode('hex')))


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

		log.debug("Entering handshake().")

		# Only the server is generating and transmitting a puzzle.
		if self.weAreServer:

			# Generate master key and derive client -and server key.
			masterKey = mycrypto.strong_random(const.MASTER_KEY_SIZE)
			self._deriveSecrets(masterKey)

			# Append random padding to obfuscate length and transmit blurb.
			padding = mycrypto.weak_random(random.randint(0, \
					const.MAX_PADDING_LENGTH))
			log.debug("Sending puzzle with %d-byte of padding." % len(padding))

			puzzle, nonce = timelock.encryptPuzzle( \
					timelock.generateRawPuzzle(masterKey))

			circuit.downstream.write(nonce + puzzle + padding)

			log.debug("Switching to state ST_WAIT_FOR_TICKET.")
			self.state = const.ST_WAIT_FOR_TICKET

		# Send a session ticket to the server (if we have one).
		elif self.weAreClient:
			stop = False
			try:
				with open(const.DATA_DIRECTORY + const.TICKET_FILE, "rb") as fd:
					masterKey = fd.read(const.MASTER_KEY_SIZE)
					ticket = fd.read(const.TICKET_LENGTH)
					fd.close()
			except IOError as e:
				log.error("Could not read session ticket from \"%s\"." % \
						(const.DATA_DIRECTORY + const.TICKET_FILE))
				stop = True

			if not stop:
				log.debug("Trying to redeem session ticket: 0x%s..." % \
						ticket.encode('hex')[:10])
				self._deriveSecrets(masterKey)
				padding = mycrypto.weak_random(random.randint(0, \
						const.MAX_PADDING_LENGTH))
				circuit.downstream.write(ticket + padding)
				self.redeemedTicket = True

		# Both sides start a noise generator to create and transmit randomness.
		# This should ``break the silence'' while the client is solving the
		# puzzle.
		self.circuit = circuit
		self.ts = TimerService(0.1, self.generateNoise)
		self.ts.startService()


	def decryptedPuzzleCallback( self, masterKey ):
		"""This method is invoked as soon as the puzzle is unlocked. The
		argument `masterKey' is the content of the unlocked puzzle."""

		log.debug("Callback invoked after solved puzzle.")

		# Sanity check to verify that we solved a real puzzle.
		if not const.MASTER_KEY_PREFIX in masterKey:
			log.critical("No MASTER_KEY_PREFIX in puzzle. What did we just " \
					"solve?")
			return

		masterKey = masterKey[len(const.MASTER_KEY_PREFIX):]
		assert len(masterKey) == const.MASTER_KEY_SIZE

		self._deriveSecrets(masterKey)

		# Make sure that noise generator has stopped before sending the
		# magic value.
		log.debug("Waiting for noise generator to stop.")
		deferred = self.ts.stopService()
		if not (deferred == None):
			log.debug("something will break.")

		# Send bridge randomness || magic value.
		log.debug("Sending magic value to server.")
		assert self.circuit
		self.circuit.downstream.write(mycrypto.weak_random(
				random.randint(0, const.MAX_PADDING_LENGTH)) + self.sendMagic)

		log.debug("Switching to state ST_WAIT_FOR_MAGIC.")
		self.state = const.ST_WAIT_FOR_MAGIC
		#self._flushSendBuffer(self.circuit)


	def sendRemote( self, circuit, data ):
		"""Encrypt, then obfuscate the given data and send it to the remote
		bridge."""

		if (data is None) or (len(data) == 0):
			return

		# Wrap the application's data in ScrambleSuit protocol messages.
		messages = message.createMessages(data)

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

				# Abort immediately if the extracted lengths do not make sense.
				if not message.saneLengths(self.totalLen, self.payloadLen):
					raise base.PluggableTransportError("Invalid message " \
							"length(s): totalLen=%d, payloadLen=%d." % \
							(self.totalLen, self.payloadLen))
				log.debug("Message header: totalLen=%d, payloadLen=%d." % \
					(self.totalLen, self.payloadLen))

			if (len(self.recvBuf) - const.HDR_LENGTH) < self.totalLen:
				return fwdBuf

			# We have a full message; let's extract it.
			else:
				log.debug("Extracting fully received protocol message.")
				rcvdHMAC = self.recvBuf[0:const.HMAC_LENGTH]
				vrfyHMAC = mycrypto.MyHMAC_SHA256_128(self.recvHMAC, \
						self.recvBuf[const.HMAC_LENGTH:(self.totalLen + \
						const.HDR_LENGTH)])

				# Abort immediately if the HMAC is invalid.
				if rcvdHMAC != vrfyHMAC:
					raise base.PluggableTransportError("Invalid HMAC!")

				fwdBuf += aes.decrypt(self.recvBuf[const.HDR_LENGTH: \
						(self.totalLen+const.HDR_LENGTH)])[:self.payloadLen]

				self.recvBuf = self.recvBuf[const.HDR_LENGTH + self.totalLen:]
				# Protocol message extracted - resetting length fields.
				self.totalLen = self.payloadLen = None

		log.debug("Unpacked %d bytes of data: 0x%s..." % \
				(len(fwdBuf), fwdBuf[:10].encode('hex')))
		return fwdBuf


	def sendLocal( self, circuit, data ):
		"""Deobfuscate, then decrypt the given data and send it to the local
		Tor client."""

		# Don't send empty data.
		if len(data) == 0 or not data:
			return

		log.debug("Processing %d bytes of incoming data." % len(data))

		# Send encrypted and obfuscated data.
		circuit.upstream.write(self.unpack(data, self.recvCrypter))


	def _receivePuzzle( self, data, circuit ):

		if len(data) < (const.PUZZLE_LENGTH + const.PUZZLE_NONCE_LENGTH):
			log.debug("Puzzle not yet fully received.")
			return

		nonce = data.read(const.PUZZLE_NONCE_LENGTH)
		#puzzle = timelock.extractPuzzle(data.read(const.PUZZLE_LENGTH))
		puzzle = data.read(const.PUZZLE_LENGTH)

		# Cache puzzle when we try our luck with the session ticket.
		if self.redeemedTicket:
			log.debug("Caching puzzle because we are using a session ticket.")
			self.cachedPuzzle = puzzle

			self._sendMagicValue(circuit, self.sendMagic)
			self.magicSent = time.time()
			#self._flushSendBuffer(circuit)

			log.debug("Switching to state ST_WAIT_FOR_MAGIC.")
			self.state = const.ST_WAIT_FOR_MAGIC
		else:
			# Prevents us from mistakenly accepting another puzzle.
			log.debug("Switching to state ST_SOLVING_PUZZLE.")
			self.state = const.ST_SOLVING_PUZZLE
			#self._solvePuzzleInProcess(puzzle)
			timelock.bruteForcePuzzle(nonce, puzzle, \
					self.decryptedPuzzleCallback)


	def _receiveTicket( self, data ):

		if len(data) < const.TICKET_LENGTH:
			log.debug("Missing %d bytes of ticket." % \
				(const.TICKET_LENGTH - len(data)))
			return

		potentialTicket = data.read(const.TICKET_LENGTH)
		log.debug("Read a potential session ticket: 0x%s..." % \
				potentialTicket.encode('hex')[:10])

		ticket = sessionticket.decryptTicket(potentialTicket)
		if ticket != None and ticket.isValid():
			log.debug("The ticket is valid. Now deriving keys.")
			self._deriveSecrets(ticket.masterKey)

		log.debug("Switching to state ST_WAIT_FOR_MAGIC.")
		self.state = const.ST_WAIT_FOR_MAGIC


	def _receiveEncryptedTicket( self, data ):

		expected = const.TICKET_LENGTH + const.MASTER_KEY_SIZE

		assert len(data) >= expected
		data = data.read(expected)

		decrypted = self.recvCrypter.decrypt(data[:expected])
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


	def _receiveClientMagic( self, data, circuit ):

		if not self._magicInData(data, self.recvMagic):
			return

		# Send server magic and next session ticket + master key.
		rawTicket, nextMasterKey = self._getSessionTicket(circuit)
		self._sendMagicValue(circuit, self.sendMagic + \
				self.sendCrypter.encrypt(rawTicket + nextMasterKey))
		self._flushSendBuffer(circuit)

		log.debug("Switching to state ST_CONNECTED.")
		self.state = const.ST_CONNECTED
		self.sendLocal(circuit, data.read())


	def _receiveServerMagic( self, data, circuit ):

		if self._magicInData(data, self.recvMagic):
			# FIXME - what to do in this situation?
			assert len(data) >= const.TICKET_LENGTH
			self._receiveEncryptedTicket(data)

			log.debug("Switching to state ST_CONNECTED.")
			self.state = const.ST_CONNECTED

			self._flushSendBuffer(circuit)
			self.sendLocal(circuit, data.read())

		elif self.redeemedTicket and ((time.time() - self.magicSent) >= 5):
			log.debug("Ticket probably not accepted. Solving the puzzle, then.")
			self._solvePuzzleInProcess(self.cachedPuzzle)
		else:
			return


	def receivedDownstream( self, data, circuit ):
		"""Data coming from the remote end point and going to the local Tor."""

		if self.circuit == None:
			self.circuit = circuit

		if self.weAreClient and self.state == const.ST_WAIT_FOR_PUZZLE:
			self._receivePuzzle(data, circuit)

		if self.weAreServer and self.state == const.ST_WAIT_FOR_TICKET:
			self._receiveTicket(data)

		if (self.weAreClient and self.state == const.ST_SOLVING_PUZZLE) or \
				(self.weAreServer and self.state == const.ST_WAIT_FOR_PUZZLE):
			log.debug("Discarding %d bytes of bogus data." % len(data.read()))

		if self.weAreServer and self.state == const.ST_WAIT_FOR_MAGIC:
			self._receiveClientMagic(data, circuit)

		if self.weAreClient and self.state == const.ST_WAIT_FOR_MAGIC:
			self._receiveServerMagic(data, circuit)

		if self.state == const.ST_CONNECTED:
			self.sendLocal(circuit, data.read())

		#log.error("Reached invalid code branch. This is probably a bug.")


	def _getSessionTicket( self, circuit ):

		log.debug("Generating new session ticket and master key.")
		nextMasterKey = mycrypto.strong_random(const.MASTER_KEY_SIZE)

		ticket = sessionticket.new(nextMasterKey)
		rawTicket = ticket.issue()

		return rawTicket, nextMasterKey


	def _magicInData( self, data, magic ):
		"""Returns True if the given `magic' is found in `data'. If not, False
		is returned."""

		preview = data.peek()

		magicIndex = preview.find(magic)
		if magicIndex == -1:
			log.debug("Found no magic value in %d-byte buffer." % len(preview))
			return False

		log.debug("Found the remote's magic value.")
		data.drain(magicIndex + const.MAGIC_LENGTH)

		return True


	def _sendMagicValue( self, circuit, magic ):
		"""Sends the given `magic' to the remote machine. Before that, the
		noise generator is stopped."""

		log.debug("Attempting to stop noise generator.")
		deferred = self.ts.stopService()
		if not deferred == None: # FIXME
			log.error("Ehm, we should have waited for deferred to return.")

		log.debug("Noise generator stopped. Now sending magic value to remote.")
		circuit.downstream.write(mycrypto.weak_random(random.randint(0, \
				const.MAX_PADDING_LENGTH)) + magic)


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


class ScrambleSuitClient( ScrambleSuitDaemon ):

	def __init__( self ):
		self.weAreClient = True
		self.weAreServer = False
		ScrambleSuitDaemon.__init__(self)


class ScrambleSuitServer( ScrambleSuitDaemon ):

	def __init__( self ):
		self.weAreServer = True
		self.weAreClient = False
		ScrambleSuitDaemon.__init__(self)
