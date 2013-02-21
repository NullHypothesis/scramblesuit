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
import obfsproxy.common.serialize as serialize
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
import packetmorpher
import processprotocol


log = logging.get_obfslogger()

def swap( a, b ):
	return (b, a)


class ScrambleSuitDaemon( base.BaseTransport ):

	def __init__( self ):

		log.debug("Initializing %s." % const.TRANSPORT_NAME)

		# Initialize the protocol' state machine.
		self.state = const.ST_WAIT_FOR_PUZZLE

		# Magic values to tell when the actual communication begins.
		self.sendMagic = self.recvMagic = None

		# Buffers for incoming and outgoing data.
		self.sendBuf = self.recvBuf = ""

		# AES instances for incoming and outgoing data.
		self.sendCrypter = mycrypto.PayloadCrypter()
		self.recvCrypter = mycrypto.PayloadCrypter()

		# Packet morpher to modify the protocol's packet length distribution.
		self.pktMorpher = None

		# Inter arrival time morpher to obfuscate inter arrival times.
		self.iatMorpher = probdist.RandProbDist(lambda: random.random() % 0.01)

		# Circuit to write data to and receive data from.
		self.circuit = None

		# Timer service to generate garbage data while puzzle is being solved.
		self.ts = None

		# Used by the unpack mechanism
		self.totalLen = None
		self.payloadLen = None


	def generateNoise( self ):
		"""Send random noise to the remote end point to confuse statistical
		classifiers. The remote machine will simply discard the data."""

		noise = mycrypto.weak_random(random.randint(0, 1000))
		log.debug("Generated %d bytes of noise. Sending now." % len(noise))
		self.circuit.downstream.transport.writeSomeData(noise)


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
			self.sendHMAC, self.recvHMAC = swap(self.sendHMAC, self.recvHMAC)
			self.sendCrypter, self.recvCrypter = swap(self.sendCrypter, \
					self.recvCrypter)
			self.sendMagic, self.recvMagic = swap(self.sendMagic, \
					self.recvMagic)
		log.debug("Local HMAC key:  %s" % self.sendHMAC.encode('hex'))
		log.debug("Remote HMAC key: %s" % self.recvHMAC.encode('hex'))

		self.pktMorpher =  packetmorpher.PacketMorpher()

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
			circuit.downstream.transport.writeSomeData( \
				timelock.generateRawPuzzle(masterKey) + padding)

			log.debug("Switching to state ST_WAIT_FOR_MAGIC.")
			self.state = const.ST_WAIT_FOR_MAGIC

		# Both sides start a noise generator to create and transmit randomness.
		# This should ``break the silence'' while the client is solving the
		# puzzle.
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

		# The session key is known now, so the magic values can be derived.
		self._deriveSecrets(masterKey)

		# Make sure that noise generator has stopped before sending the
		# magic value.
		log.debug("Waiting for noise generator to stop.")
		deferred = self.ts.stopService()
		if not (deferred == None):
			log.debug("something will break.")

		# Send bridge randomness || magic value.
		log.debug("Sending magic value to server.")
		self.circuit.downstream.transport.writeSomeData(mycrypto.weak_random(random.randint(0, \
				const.MAX_PADDING_LENGTH)) + self.sendMagic)

		log.debug("Switching to state ST_WAIT_FOR_MAGIC.")
		self.state = const.ST_WAIT_FOR_MAGIC

		# Flush the buffered data, Tor wanted to send in the meantime.
		if len(self.sendBuf):
			log.debug("Flushing %d bytes of buffered data from local Tor." % \
				len(self.sendBuf))
			self.sendRemote(self.circuit, self.sendBuf)
			self.sendBuf = ""


	def sendRemote( self, circuit, data ):
		"""Encrypt, then obfuscate the given data and send it to the remote
		bridge."""

		if len(data) == 0 or not data:
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
		choppedBlurbs = chopper(blurb)

		for blurb in choppedBlurbs:
			# Random sleeps to obfuscate inter arrival times.
			duration = self.iatMorpher.randomSample()
			log.debug("Sleeping for %.4f seconds before sending data." % duration)
			time.sleep(duration)
			circuit.downstream.transport.writeSomeData(blurb)


	def unpack( self, data, crypter ):

		log.debug("Getting %d bytes to unpack." % len(data))

		# Input buffer which is not yet processed and forwarded.
		self.recvBuf += data
		fwdBuf = ""

		# Keep trying to unpack as long as there seems to be enough data.
		while len(self.recvBuf) >= const.HDR_LENGTH:

			# Extract length fields if we don't have them already.
			if self.totalLen == None:# and self.payloadLen == None:
				self.totalLen = serialize.ntohs(crypter.decrypt(self.recvBuf[16:18]))
				self.payloadLen = serialize.ntohs(crypter.decrypt(self.recvBuf[18:20]))
				log.debug("totalLen=%d, payloadLen=%d" % \
					(self.totalLen, self.payloadLen))

			# Current protocol message not fully received yet.
			if (len(self.recvBuf) - const.HDR_LENGTH) < self.totalLen:
				log.debug("Protocol message not yet fully received.")
				return fwdBuf

			# Sufficient data -> remove packet from input buffer.
			else:
				rcvdHMAC = self.recvBuf[:const.HMAC_LENGTH]
				vrfyHMAC = mycrypto.MyHMAC_SHA256_128(self.recvHMAC, self.recvBuf[const.HMAC_LENGTH:(self.totalLen+const.HDR_LENGTH)])
				if rcvdHMAC != vrfyHMAC:
					log.debug("WARNING: HMACs (%s / %s) differ!" % \
						(rcvdHMAC.encode('hex'), vrfyHMAC.encode('hex')))
				else:
					log.debug("HMAC of message successfully verified.")

				fwdBuf += crypter.decrypt(self.recvBuf[const.HDR_LENGTH: \
						(self.totalLen+const.HDR_LENGTH)])[:self.payloadLen]

				self.recvBuf = self.recvBuf[const.HDR_LENGTH + self.totalLen:]
				# Protocol message extracted - resetting length fields.
				self.totalLen = self.payloadLen = None

		log.debug("Flushing %d bytes of data: %s..." % (len(fwdBuf), fwdBuf[:10].encode('hex')))
		return fwdBuf


	def sendLocal( self, circuit, data ):
		"""Deobfuscate, then decrypt the given data and send it to the local
		Tor client."""

		# Don't send empty data.
		if len(data) == 0 or not data:
			return

		log.debug("Attempting to send %d bytes of data to local." % len(data))

		# Send encrypted and obfuscated data.
		circuit.upstream.write(self.unpack(data, self.recvCrypter))


	def _receivePuzzle( self, data ):

		if len(data) < const.PUZZLE_LENGTH:
			log.debug("Still missing %d bytes of puzzle." % \
					(const.PUZZLE_LENGTH - len(data)))
			return

		puzzle = timelock.extractPuzzle(data.read(const.PUZZLE_LENGTH))
		t = timelock.new()

		# Prevents us from mistakenly accepting another puzzle.
		log.debug("Switching to state ST_SOLVING_PUZZLE.")
		self.state = const.ST_SOLVING_PUZZLE

		# Solve puzzle in subprocess and invoke callback when finished.
		log.debug("Attempting to unlock puzzle in dedicated process.")

		# Python interpreter.
		executable = sys.executable
		pp = processprotocol.MyProcessProtocol(puzzle, \
				self.decryptedPuzzleCallback)

		# Solve puzzle in dedicated process.
		log.debug("We are in: %s" % os.getcwd())
		reactor.spawnProcess(pp, executable, [executable, 
			# FIXME - need to use relative paths here.
			"/home/phw/sw/pyobfsproxy/obfsproxy/transports/timelock.py"], \
			env=os.environ)


	def receivedDownstream( self, data, circuit ):
		"""Data coming from the remote end point and going to the local Tor."""

		self.circuit = circuit

		if self.state == const.ST_CONNECTED:
			self.sendLocal(circuit, data.read())

		elif self.weAreClient and self.state == const.ST_WAIT_FOR_PUZZLE:
			self._receivePuzzle(data)

		elif self.state == const.ST_WAIT_FOR_MAGIC:
			if not self._magicInData(data, self.recvMagic):
				return

			if self.weAreServer:
				self._sendMagicValue(circuit, self.sendMagic)
			log.debug("Switching to state ST_CONNECTED.")
			self.state = const.ST_CONNECTED
			self.sendLocal(circuit, data.read())

		elif (self.weAreClient and self.state == const.ST_SOLVING_PUZZLE) or \
				(self.weAreServer and self.state == const.ST_WAIT_FOR_PUZZLE):
			log.debug("Discarding %d bytes of bogus data." % len(data.read()))

		else:
			log.error("Reached invalid code branch. This is probably a bug.")


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
		circuit.downstream.transport.writeSomeData(mycrypto.weak_random(random.randint(0, \
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
