#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
The scramblesuit module implements the ScrambleSuit obfuscation protocol.
For more details, check out http://www.cs.kau.se/philwint/scramblesuit/
"""

from twisted.internet import error
from twisted.internet import reactor
from twisted.internet import protocol
from twisted.application.internet import TimerService


import obfsproxy.transports.base as base
import obfsproxy.common.log as logging

import os
import sys
import random
import pickle
import struct
import string
import time

import probdist
import timelock
import mycrypto
import message


# Key size (in bytes) for the AES session key and its IV.
SESSION_KEY_SIZE = IV_SIZE = 32

# Used to derive other key material, e.g. for AES and HMAC.
MASTER_SECRET_SIZE = 32

# The maximum padding length to be appended to the puzzle.
MAX_PADDING_LENGTH = 8192

# Length of the puzzle (in bytes). The client needs to know the size to know
# when to start extracting the puzzle.
PUZZLE_LENGTH = 192

MAGIC_LENGTH = 32

# States which are used for the protocol state machine.
ST_WAIT_FOR_PUZZLE = 0
ST_SOLVING_PUZZLE = 1
ST_WAIT_FOR_MAGIC = 2
ST_CONNECTED = 3

# Length of len field (in bytes).
HDR_LENGTH = 16 + 2 + 2

# Length of HMAC-SHA256-128.
HMAC_LENGTH = 16

# TODO - what do we choose? should fit into an ethernet (non-jumbo) frame
MTU = 1448

# The prefix before the session key which is ``locked'' inside the time-lock
# puzzle.  The client looks for this prefix to verify that the puzzle was
# unlocked successfully.
MASTER_KEY_PREFIX = "Session key: "

# Used in log messages.
TRANSPORT_NAME = "ScrambleSuit"



log = logging.get_obfslogger()



def ntohs( data ):
	return struct.unpack('!H', data)



def htons( data ):
	return struct.pack('!H', data)



class PacketMorpher( object ):
	"""Provides an interface to morph large chunks of bytes to a given target
	probability distribution. This is implemented by naively sampling the
	target probability distribution."""

	def __init__( self, dist=None ):
		"""Initialize the PacketMorpher with a discrete probability
		distribution. If none is given, a distribution is randomly
		generated."""

		self.dist = dist if dist else \
			probdist.RandProbDist(lambda: random.randint(1, MTU))


	def morph( self, dataLen ):
		"""Based on `dataLen', the length of the data to morph, this function
		returns a chopper function which is used to chop the data as well as
		the length of padding which is appended to the last protocol
		message."""

		breakPoints = []
		lastBreakPoint = 0
		progress = 0

		while progress < dataLen:
			newBreakPoint = progress + self.dist.randomSample()
			breakPoints.append((lastBreakPoint, newBreakPoint))
			lastBreakPoint = newBreakPoint
			progress += newBreakPoint

		paddingLen = progress - dataLen
		breakPoints.append((lastBreakPoint, progress))

		chopper = lambda data: [data[x:y] for (x, y) in breakPoints]

		return (chopper, paddingLen)



class PayloadScrambler:
	"""Obfuscates data after encryption to make analysis harder. Also, this
	should make it possible to evade high-entropy filters."""

	def __init__( self ):
		log.debug("Initializing payload scrambler.")


	def encode( self, data ):
		"""Encodes the given `data' to be sent over the wire."""

		return data


	def decode( self, data ):
		"""Decodes the given `data' and."""

		return data



class MyProcessProtocol( protocol.ProcessProtocol ):
	"""Used to communicate with the time-lock solver which is an external
	python process. This class is able to send a puzzle to the process and
	retrieve the result."""


	def __init__( self, puzzle, callback ):

		log.debug("Initializing process protocol.")
		self.puzzle = puzzle
		self.callback = callback


	def connectionMade( self ):
		"""Writes the pickled time-lock puzzle to the external processes
		stdin."""

		log.debug("Handing pickled time-lock puzzle to external process.")
		pickle.dump(self.puzzle, self.transport)
		self.transport.closeStdin()


	def outReceived( self, data ):
		"""Reads the content of the unlocked puzzle from the external processes
		stdout. Afterwards, the result is delivered using a callback."""

		log.debug("Read unlocked message from the external process.")
		self.callback(data.strip())



class ScrambleSuitDaemon( base.BaseTransport ):

	def __init__( self ):

		log.debug("Initializing %s." % TRANSPORT_NAME)

		if self.weAreClient:
			log.debug("Switching to state ST_WAIT_FOR_PUZZLE.")
			self.state = ST_WAIT_FOR_PUZZLE
			#self.sendCrypter = self.clientCrypter
			#self.recvCrypter = self.serverCrypter
		elif self.weAreServer:
			log.debug("Switching to state ST_WAIT_FOR_MAGIC.")
			self.state = ST_WAIT_FOR_PUZZLE
			#self.state = ST_WAIT_FOR_MAGIC
			#self.recvCrypter = self.clientCrypter
			#self.sendCrypter = self.serverCrypter

		self.clientMagic = self.serverMagic = None
		self.outbuf = self.inbuf = ""
		#self.unpackBuf = ""
		self.rcvBuf = ""
		self.circuit = None
		self.scrambler = PayloadScrambler()
		# FIXME - this should probably be called sendCrypter and rcvCrypter
		self.clientCrypter = mycrypto.PayloadCrypter()
		self.serverCrypter = mycrypto.PayloadCrypter()
		self.pktMorpher = None
		
		self.ts = None
		# Used by the unpack mechanism
		self.totalLen = None
		self.payloadLen = None
		# inter arrival time obfuscator
		self.iatMorpher = probdist.RandProbDist(lambda: random.random() % 0.05)


	def generateNoise( self ):
		"""Send random noise to the remote end point to confuse statistical
		classifiers. The remote machine will simply discard the data."""

		noise = mycrypto.weak_random(random.randint(0, 1000))
		log.debug("Generated %d bytes of noise. Sending now." % len(noise))
		self.circuit.downstream.write(noise)


	def _deriveSecrets( self, masterSecret ):
		"""Derives session keys (AES keys, counter nonces, HMAC keys and magic
		values) from the given master secret. All key material is derived using
		HKDF-SHA256."""

		log.debug("Master secret: 0x%s." % masterSecret.encode('hex'))

		# We need key material for two magic values, symmetric keys, nonces and
		# HMACs. All of them are 32 bytes in size.
		hkdf = mycrypto.HKDF_SHA256(masterSecret, "", 32 * 8)
		okm = hkdf.expand()

		# Set the symmetric AES keys.
		self.clientCrypter.setSessionKey(okm[0:32],  okm[32:64])
		self.serverCrypter.setSessionKey(okm[64:96], okm[96:128])

		# Derive a magic value for the client as well as the server. They must
		# be distinct to prevent fingerprinting (e.g. look for two identical
		# 256-bit strings).
		self.clientMagic = okm[128:160]
		self.serverMagic = okm[160:192]
		self.remoteMagic = self.clientMagic if self.weAreServer else \
				self.serverMagic

		# Set the HMAC keys.
		self.localHMAC = okm[192:224]
		self.remoteHMAC = okm[224:256]
		if self.weAreServer:
			tmp = self.localHMAC
			self.localHMAC = self.remoteHMAC
			self.remoteHMAC = tmp
		log.debug("Local HMAC key:  %s" % self.localHMAC.encode('hex'))
		log.debug("Remote HMAC key: %s" % self.remoteHMAC.encode('hex'))

		self.pktMorpher =  PacketMorpher()

		log.debug("Magic values derived from session key: client=0x%s, " \
			"server=0x%s." % (self.clientMagic.encode('hex'), \
			self.serverMagic.encode('hex')))


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

			rawPuzzle = self.getPuzzle()
			log.debug("Successfully generated %d-byte puzzle." % \
				len(rawPuzzle))

			# Append random padding to obfuscate length and transmit blurb.
			padding = mycrypto.weak_random(random.randint(0, MAX_PADDING_LENGTH))
			log.debug("Sending puzzle with %d bytes of random padding." % \
					len(padding))
			circuit.downstream.write(rawPuzzle + padding)
			# FIXME - like obfs3, we could use repr() to print the puzzle.

			log.debug("Switching to state ST_WAIT_FOR_MAGIC.")
			self.state = ST_WAIT_FOR_MAGIC

		# Both sides start a noise generator to create and transmit randomness.
		# This should ``break the silence'' while the client is solving the
		# puzzle.
		self.ts = TimerService(1, self.generateNoise)
		self.ts.startService()


	def getPuzzle( self ):
		"""Generates the time-lock puzzle for the client to solve. This will
		yield the symmetric session key."""

		# Generate master secret and derive client -and server secret.
		masterSecret = mycrypto.strong_random(MASTER_SECRET_SIZE)
		self._deriveSecrets(masterSecret)

		# Create puzzle which ``locks'' the shared session key.
		riddler = timelock.new()
		puzzle = riddler.generatePuzzle(MASTER_KEY_PREFIX + \
			masterSecret)

		# Convert base 10 numbers to raw strings.
		rawPuzzle = bytearray()
		rawPuzzle = [timelock.dump(x) for x in \
			[puzzle["n"], puzzle["a"], puzzle["Cm"]]]

		# Return single concatenated string.
		return reduce(lambda x, y: x + y, rawPuzzle)


	def decryptedPuzzleCallback( self, sharedSecret ):
		"""This method is invoked as soon as the puzzle is unlocked. The
		argument `sharedSecret' is the content of the unlocked puzzle."""

		log.debug("Callback invoked after solved puzzle.")

		# Sanity check to verify that we solved a real puzzle.
		if not MASTER_KEY_PREFIX in sharedSecret:
			log.critical("No MASTER_KEY_PREFIX in puzzle. What did we just " \
					"solve?")
			return

		sharedSecret = sharedSecret[len(MASTER_KEY_PREFIX):]

		# The session key is known now, so the magic values can be derived.
		self._deriveSecrets(sharedSecret)

		# Make sure that noise generator has stopped before sending the
		# magic value.
		log.debug("Waiting for noise generator to stop.")
		deferred = self.ts.stopService()
		if not (deferred == None):
			log.debug("something will break.")

		# Send bridge randomness || magic value.
		log.debug("Sending magic value to server.")
		self.circuit.downstream.write(mycrypto.weak_random(random.randint(0, \
				MAX_PADDING_LENGTH)) + self.clientMagic)

		log.debug("Switching to state ST_WAIT_FOR_MAGIC.")
		self.state = ST_WAIT_FOR_MAGIC

		# Flush the buffered data, Tor wanted to send in the meantime.
		if len(self.outbuf):
			log.debug("Flushing %d bytes of buffered data from local Tor." % \
				len(self.outbuf))
			self.sendRemote(self.circuit, self.outbuf)
			self.outbuf = ""


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
		messages[-1].addPadding(paddingLen)

		# Encrypt and authenticate all messages.
		blurb = string.join([msg.encryptAndHMAC(self.clientCrypter \
				if self.weAreClient else self.serverCrypter, self.localHMAC) \
				for msg in messages], '')

		# Chop the encrypted blurb to fit the target probability distribution.
		choppedBlurbs = chopper(blurb)

		for blurb in choppedBlurbs:
			# Random sleeps to obfuscate inter arrival times.
			duration = self.iatMorpher.randomSample()
			log.debug("Sleeping for %.4f seconds before sending data." % duration)
			time.sleep(duration)
			circuit.downstream.write(blurb)


	def unpack( self, data, crypter ):

		log.debug("Getting %d bytes to unpack." % len(data))

		# Input buffer which is not yet processed and forwarded.
		self.rcvBuf += data
		fwdBuf = ""

		# Keep trying to unpack as long as there seems to be enough data.
		while len(self.rcvBuf) >= HDR_LENGTH:

			# Extract length fields if we don't have them already.
			if self.totalLen == None:# and self.payloadLen == None:
				self.totalLen = ntohs(crypter.decrypt(self.rcvBuf[16:18]))[0]
				self.payloadLen = ntohs(crypter.decrypt(self.rcvBuf[18:20]))[0]
				log.debug("totalLen=%d, payloadLen=%d" % \
					(self.totalLen, self.payloadLen))

			# Current protocol message not fully received yet.
			if (len(self.rcvBuf) - HDR_LENGTH) < self.totalLen:
				log.debug("Protocol message not yet fully received.")
				return fwdBuf

			# Sufficient data -> remove packet from input buffer.
			else:
				rcvdHMAC = self.rcvBuf[:HMAC_LENGTH]
				vrfyHMAC = mycrypto.MyHMAC_SHA256_128(self.remoteHMAC, self.rcvBuf[HMAC_LENGTH:(self.totalLen+HDR_LENGTH)])
				if rcvdHMAC != vrfyHMAC:
					log.debug("WARNING: HMACs (%s / %s) differ!" % \
						(rcvdHMAC.encode('hex'), vrfyHMAC.encode('hex')))
				else:
					log.debug("HMAC of message successfully verified.")

				fwdBuf += crypter.decrypt(self.rcvBuf[HDR_LENGTH: \
						(self.totalLen+HDR_LENGTH)])[:self.payloadLen]

				self.rcvBuf = self.rcvBuf[HDR_LENGTH + self.totalLen:]
				# Protocol message extracted - resetting length fields.
				self.totalLen = self.payloadLen = None

		log.debug("Flushing %d bytes of data: %s..." % (len(fwdBuf), fwdBuf[:10].encode('hex')))
		return fwdBuf


	def sendLocal( self, circuit, data ):
		"""Deobfuscate, then decrypt the given data and send it to the local
		Tor client."""

		log.debug("Attempting to send %d bytes of data to local." % len(data))

		# Don't send empty data.
		if len(data) == 0 or not data:
			return

		if self.weAreServer:
			crypter = self.clientCrypter
		else:
			crypter = self.serverCrypter

		# Send encrypted and obfuscated data.
		circuit.upstream.write(
				self.unpack( self.scrambler.decode(data), crypter)
			)


	def _receivePuzzle( self, data ):

		if len(data) < PUZZLE_LENGTH:
			log.debug("Only have %d bytes out of %d-byte "
					"puzzle so far." % (len(data), PUZZLE_LENGTH))
			return

		puzzle = timelock.extractPuzzleFromBlurb(data.read(PUZZLE_LENGTH))
		t = timelock.new()

		# Prevents us from mistakenly accepting another puzzle.
		log.debug("Switching to state ST_SOLVING_PUZZLE.")
		self.state = ST_SOLVING_PUZZLE

		# Solve puzzle in subprocess and invoke callback when finished.
		log.debug("Attempting to unlock puzzle in dedicated process.")

		# Python interpreter.
		executable = sys.executable
		pp = MyProcessProtocol(puzzle, self.decryptedPuzzleCallback)

		# Solve puzzle in dedicated process.
		log.debug("We are in: %s" % os.getcwd())
		reactor.spawnProcess(pp, executable, [executable, 
			# FIXME - need to use relative paths here.
			"/home/phw/sw/pyobfsproxy/obfsproxy/transports/timelock.py"], \
			env=os.environ)


	def receivedDownstream( self, data, circuit ):
		"""Data coming from the remote end point and going to the local Tor."""

		self.circuit = circuit

		if self.state == ST_CONNECTED:
			self.sendLocal(circuit, data.read())

		elif self.weAreClient and self.state == ST_WAIT_FOR_PUZZLE:
			self._receivePuzzle(data)

		elif self.state == ST_WAIT_FOR_MAGIC:
			if not self._magicInData(data, self.remoteMagic):
				return

			if self.weAreServer:
				self._sendMagicValue(circuit, self.serverMagic)
			log.debug("Switching to state ST_CONNECTED.")
			self.state = ST_CONNECTED
			self.sendLocal(circuit, data.read())

		# Right now, we only expect pseudo-data which can be discarded safely.
		elif (self.weAreClient and self.state == ST_SOLVING_PUZZLE) or \
				(self.weAreServer and self.state == ST_WAIT_FOR_PUZZLE):
			log.debug("We got %d bytes of pseudo-data in invalid state " \
				"%d. Discarding data." % (len(data.read()), self.state))

		else:
			 raise base.PluggableTransportError("%s: Reached invalid code " \
					"branch. This is probably a bug." % TRANSPORT_NAME)


	def _magicInData( self, data, magic ):

		preview = data.peek()

		index = preview.find(magic)
		if index == -1:
			log.debug("Did not find magic value in " \
					"%d-byte buffer yet." % len(preview))
			return False

		log.debug("Found the remote's magic value.")
		data.drain(index + MAGIC_LENGTH)

		return True


	def _sendMagicValue( self, circuit, magic ):

		log.debug("Stopping noise generator.")
		deferred = self.ts.stopService()
		if not deferred == None:
			log.error("Ehm, we should have waited for deferred to return.")

		# Got the client's magic value. Now send the server's magic.
		log.debug("Noise generator stopped. Now sending magic value to remote.")
		circuit.downstream.write(mycrypto.weak_random(random.randint(0, 100)) \
				+ magic)


	def receivedUpstream( self, data, circuit ):
		"""Data coming from the local Tor client and going to the remote
		bridge. If the data can't be sent immediately (in state ST_CONNECTED)
		it is buffered to be transmitted later."""

		# Send locally received data to the remote end point.
		if self.state == ST_CONNECTED:
			self.sendRemote(circuit, data.read())

		# Buffer data we are not ready to transmit yet. It will get flushed
		# once the puzzle is solved and the connection established.
		else:
			blurb = data.read()
			self.outbuf += blurb
			log.debug("Buffering %d bytes of outgoing data." % len(blurb))


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
