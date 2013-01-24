#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
The scramblesuit module implements the ScrambleSuit protocol.
For more details, check out http://www.cs.kau.se/philwint/scramblesuit/
"""

from twisted.internet import error
from twisted.internet import reactor
from twisted.internet import protocol
from twisted.application.internet import TimerService

from Crypto.Hash import SHA256
from Crypto.Hash import HMAC
from Crypto.Util import Counter
from Crypto.Cipher import AES
from Crypto.Cipher import ARC4

import obfsproxy.transports.base as base
import obfsproxy.common.log as logging

import os
import sys
import random
import pickle
import struct
import time

import probdist
import timelock


# Key size (in bytes) for the AES session key and its IV.
SESSION_KEY_SIZE = IV_SIZE = 16

# Used to derive client and server key which are used for AES and its IV.
SHARED_SECRET_SIZE = 16

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
SESSION_KEY_PREFIX = "Session key: "

# Used in log messages.
TRANSPORT_NAME = "ScrambleSuit"


log = logging.get_obfslogger()


key = "0123456789abcdef"
def MyHMAC_SHA256_128( key, msg ):
	"""Wraps Crypto.Hash's HMAC."""

	assert(len(key) == 16)

	h = HMAC.new(key, msg, SHA256)

	# Return HMAC truncated to 128 out of 256 bits.
	return h.digest()[:16]



def MySHA256( msg ):
	"""Wraps Crypto.Hash's SHA256 and returns the binary digest."""

	h = SHA256.new()
	h.update(msg)
	return h.digest()



def strong_random( size ):
	"""Returns `size' bytes of strong randomness which is suitable for
	cryptographic use."""

	return os.urandom(size)



def weak_random( size ):
	"""Returns `size' bytes of weak randomness which can be used to pad
	application data but is not suitable for cryptographic use."""

	# TODO - Get a function which does not exhaust the OSes entropy pool.
	return os.urandom(size)



def ntohs( data ):
	return struct.unpack('!H', data)



def htons( data ):
	return struct.pack('!H', data)



def addHeader( crypter, payload, padding="" ):
	"""Add header information to the given chunk of data and return
	ready-to-send protocol message."""

	# TODO - the following should be an assert() since this should not happen.
	# Are we exceeding the MTU after adding the header?
	if (HDR_LENGTH + len(payload) + len(padding)) > MTU:
		log.info("WARNING: padding would be more than configured MTU.")

	payloadLen = htons(len(payload))
	totalLen = htons(len(payload) + len(padding))
	packet = crypter.encrypt(totalLen + payloadLen + payload + padding)
	hmac = MyHMAC_SHA256_128(key, packet)
	log.debug("Prepending HMAC: %s." % hmac.encode('hex'))

	return hmac + packet



def padPacket( packet, padlen, padchar="\0" ):

	# Are we exceeding the MTU after padding?
	if (len(packet) + padlen) > MTU:
		log.info("WARNING: padding would be more than configured MTU.")

	return packet + (padchar * padlen)



class PacketMorpher:
	"""Provides an interface to morph chunks of network data to a given target
	probability distribution. This is implemented using naive sampling which
	does not consider the source probability distribution."""


	def __init__( self, crypter, dist=None ):
		"""Initialize the PacketMorpher with a packet probability distribution.
		If none is given, a distribution is randomly generated."""

		#self.dist = dist if dist else PacketSizeDistribution()
		self.dist = dist if dist else \
			probdist.RandProbDist(lambda: random.randint(1, MTU))
		# Create statistics to be able to calculate overhead.
		self.payloadCtr = 0
		self.paddingCtr = 0
		self.crypter = crypter


	def morph( self, payload ):
		"""Transform the given chunk of payload to ready-to-transmit packets
		whose length matches the configured target frequency distribution."""

		# List of final packets which are sent over the wire.
		packets = []

		log.debug("Morphing %d bytes of data." % len(payload))

		# Get target length by randomly sampling the target frequency
		# distribution.
		targetLength = (self.dist.randomSample() - HDR_LENGTH)

		log.debug("Samples packet target length: %d bytes." % targetLength)

		# Chunk equal or smaller than target: Pad.
		if len(payload) <= targetLength:
			padding = "\0" * (targetLength - len(payload))
			packet = addHeader(self.crypter, payload, padding)

			# Update statistics.
			self.payloadCtr += len(payload)
			self.paddingCtr += len(padding)

			log.debug("PacketMorpher: Adding %d bytes of padding." % \
				len(padding))

			# FIXME - put this somewhere else
			log.debug("Data overhead: %f%%." % \
				(100/(float(self.payloadCtr) / \
					(self.paddingCtr if self.paddingCtr > 0 else 1))))

			return packets + [packet]

		# Chunk larger than target: Split.
		else:
			packets.append(addHeader(self.crypter, payload[:targetLength]))
			self.payloadCtr += len(payload[:targetLength])

			log.debug("PacketMorpher: Splitting packet.")

			return packets + self.morph(payload[targetLength:])



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



class PayloadCrypter:
	"""Encrypts plain Tor data using AES. The encrypted data is then passed on
	to the obfuscation component PayloadScrambler."""

	# FIXME - in here we can handle authenticated encryption.

	def __init__( self ):

		log.debug("Initializing payload crypter.")
		self.sessionKey = None
		self.crypter = None
		self.counter = None


	def setSessionKey( self, key, iv ):
		"""Set the AES session key and initialize counter mode."""

		log.debug("Setting session key for payload crypter: 0x%s." % \
			key.encode('hex'))
		log.debug("Setting IV for payload crypter: 0x%s." % \
			iv.encode('hex'))
		self.sessionKey = key
		self.counter = Counter.new(128, initial_value=long(iv.encode('hex'), 16))
		self.crypter = AES.new(key, AES.MODE_CTR, counter=self.counter)


	def encrypt( self, data ):
		"""Encrypts the given `data' using AES."""

		# Send unencrypted data if AES is not initialized yet.
		if self.crypter == None:
			return data
		else:
			return self.crypter.encrypt(data)


	# Encryption equals decryption in AES CTR.
	decrypt = encrypt



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


# class ScrambleSuitMessage:
# 	def __init__( self, payload="", paddingLen=0 ):
# 		self.payload = payload
# 		self.padding = paddingLen * '\0'
# 		self.encryptedMsg = ""
# 
# 		self.hmac = ""
# 		self.totalLen = ""
# 		self.payloadLen = ""
# 
# 	def dump( self ):
# 		"""Return ScrambeSuit message as byte string which is ready to be sent
# 		over the wire."""
# 		pass
# 
# 	def addHeader( self, key, crypter ):
# 
# 		assert(len(self.payload) > 0)
# 
# 		self.payloadLen = len(self.payload)
# 		self.totalLen = self.payloadLen + len(self.padding)
# 
# 		encryptedMsg = crypter.encrypt(htons(totalLen) + \
# 			htons(payloadLen) + self.payload + self.padding)
# 
# 		# Finally, authenticate the encrypted protocol message using the HMAC.
# 		self.hmac = MyHMAC_SHA256_128(key, encryptedMsg)
# 
# 
# 	def extractPayload( self ):
# 		# Verify HMAC.



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
		self.clientCrypter = PayloadCrypter()
		self.serverCrypter = PayloadCrypter()
		self.pktMorpher = PacketMorpher(self.clientCrypter if self.weAreClient \
			else self.serverCrypter)
		self.ts = None
		# Used by the unpack mechanism
		self.totalLen = None
		self.payloadLen = None
		# inter arrival time obfuscator
		self.iatMorpher = probdist.RandProbDist(lambda: random.random() % 0.05)

	def generateNoise( self ):
		"""Send random noise to the remote end point to confuse statistical
		classifiers. The remote machine will simply discard the data."""

		noise = weak_random(random.randint(0, 1000))
		log.debug("Generated %d bytes of noise. Sending now." % len(noise))
		self.circuit.downstream.write(noise)


	def spawnPuzzleProcess( self, puzzle ):

		# Python interpreter.
		executable = sys.executable
		pp = MyProcessProtocol(puzzle, self.decryptedPuzzleCallback)

		# Solve puzzle in dedicated process.
		log.debug("We are in: %s" % os.getcwd())
		reactor.spawnProcess(pp, executable, [executable, 
			# FIXME - need to use relative paths here.
			"/home/phw/sw/pyobfsproxy/obfsproxy/transports/timelock.py"], \
			env=os.environ)


	def deriveSecrets( self, sharedSecret ):
		"""Derives the two magic values (one for server and client, each) from
		the session key. The magic values are necessary to tell when the random
		garbage stops and the encrypted data starts."""

		log.debug("Master secret: 0x%s." % sharedSecret.encode('hex'))

		# Derive secrets specific to client and server.
		clientSecret = MySHA256("Client" + sharedSecret)#[:SHARED_SECRET_SIZE]
		serverSecret = MySHA256("Server" + sharedSecret)#[SHARED_SECRET_SIZE:]

		# Generate two symmetric session keys.
		self.clientCrypter.setSessionKey(clientSecret[:SESSION_KEY_SIZE], \
			clientSecret[IV_SIZE:])
		self.serverCrypter.setSessionKey(serverSecret[:SESSION_KEY_SIZE], \
			serverSecret[IV_SIZE:])

		# Derive a magic value for the client as well as the server. They must
		# be distinct to prevent fingerprinting (e.g. look for two identical
		# 256-bit strings).
		self.clientMagic = MySHA256(clientSecret)
		self.serverMagic = MySHA256(serverSecret)
		self.remoteMagic = self.clientMagic if self.weAreServer else \
				self.serverMagic
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

			# The session key is known now, so the magic values can be derived.
			#self.deriveSecrets()

			# Append random padding to obfuscate length and transmit blurb.
			padding = weak_random(random.randint(0, MAX_PADDING_LENGTH))
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
		sharedSecret = strong_random(SHARED_SECRET_SIZE)

		log.debug("Deriving secrets from the master secret.")
		self.deriveSecrets(sharedSecret)

		# Create puzzle which ``time-locks'' the shared session key.
		riddler = timelock.new()
		puzzle = riddler.generatePuzzle(SESSION_KEY_PREFIX + \
			sharedSecret)
		log.debug("Generated puzzle: %s." % str(puzzle))

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
		if not SESSION_KEY_PREFIX in sharedSecret:
			log.critical("No SESSION_KEY_PREFIX in puzzle. What did we just " \
					"solve?")
			return

		sharedSecret = sharedSecret[len(SESSION_KEY_PREFIX):]

		# The session key is known now, so the magic values can be derived.
		self.deriveSecrets(sharedSecret)

		# Make sure that noise generator has stopped before sending the
		# magic value.
		log.debug("Waiting for noise generator to stop.")
		deferred = self.ts.stopService()
		if not (deferred == None):
			log.debug("something will break.")

		# Send bridge randomness || magic value.
		log.debug("Sending magic value to server.")
		self.circuit.downstream.write(weak_random(random.randint(0, \
				MAX_PADDING_LENGTH)) + self.clientMagic)

		log.debug("Switching to state ST_WAIT_FOR_MAGIC.")
		self.state = ST_WAIT_FOR_MAGIC

		# Flush the buffered data, Tor wanted to send in the meantime.
		if len(self.outbuf):
			log.debug("Flushing %d bytes of buffered data from local Tor." % \
				len(self.outbuf))

			packets = self.pktMorpher.morph(self.outbuf)
			for packet in packets:
				self.sendRemote(self.circuit, packet)

			self.outbuf = ""


	def sendRemote( self, circuit, data ):
		"""Encrypt, then obfuscate the given data and send it to the remote
		bridge."""

		# Don't send empty data.
		if len(data) == 0 or not data:
			return

		# Sleep a random time period in order to obfuscate inter arrival times.
		duration = self.iatMorpher.randomSample()
		log.debug("Sleeping for %.4f seconds before sending data." % duration)
		time.sleep(duration)

		log.debug("-> Sending %d bytes to the remote." % len(data))

		# Send encrypted and obfuscated data.
		circuit.downstream.write(self.scrambler.encode(data))


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
				#return ""
				return fwdBuf
			# Sufficient data -> remove packet from input buffer.
			else:
				rcvdHMAC = self.rcvBuf[:HMAC_LENGTH]
				vrfyHMAC = MyHMAC_SHA256_128(key, self.rcvBuf[HMAC_LENGTH:(self.totalLen+HDR_LENGTH)])
				if rcvdHMAC != vrfyHMAC:
					log.debug("WARNING: HMACs (%s / %s) differ!" % \
						(rcvdHMAC.encode('hex'), vrfyHMAC.encode('hex')))
				else:
					log.debug("HMAC (%s / %s) verified!" % \
						(rcvdHMAC.encode('hex'), vrfyHMAC.encode('hex')))

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
		self.spawnPuzzleProcess(puzzle)


	def receivedDownstream( self, data, circuit ):
		"""Data coming from the remote end point and going to the local Tor."""

		log.debug("<- Received %d bytes from remote." % len(data))
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
		circuit.downstream.write(weak_random(random.randint(0, 100)) + magic)


	def receivedUpstream( self, data, circuit ):
		"""Data coming from the local Tor client and going to the remote
		bridge. If the data can't be sent immediately (in state ST_CONNECTED)
		it is buffered to be transmitted later."""

		# Send locally received data to the remote end point.
		if self.state == ST_CONNECTED:
			packets = self.pktMorpher.morph(data.read())
			for packet in packets:
				log.debug("Sending one of the morphed packets.")
				self.sendRemote(circuit, packet)

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
