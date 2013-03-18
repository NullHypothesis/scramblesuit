#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
A Python implementation of time-lock puzzles.

The underlying theory was discussed in the 1996 paper by Rivest, Shamir and
Wagner named "Time-lock Puzzles and Timed-release Crypto":
http://people.csail.mit.edu/rivest/RivestShamirWagner-timelock.ps
The code makes it possible to easily create a cryptographic puzzle which can
not be decrypted before a given time period.
"""

import os
import sys
import gmpy
import math
import time
import random
import pickle
import struct

from Crypto.Util import Counter
from Crypto.Util import number
from Crypto.Cipher import AES
from twisted.internet import reactor

import obfsproxy.common.log as logging

import const
import primes
import util
import mycrypto
import processprotocol


log = logging.get_obfslogger()


def stressTest( seconds ):
	"""Tests how many puzzles can be generated within the given amount of
	seconds. The number is returned."""

	start = time.time()
	r = os.urandom(16)
	count = 0

	while (time.time() - start) < seconds:
		t = TimeLockPuzzle()
		puzzle = t.generatePuzzle(r)
		count += 1
	return count


def extractPuzzle( data ):
	"""Extracts a time-lock puzzles out of the given chunk of data. The puzzle
	is then returned as a ready-to-solve dictionary."""

	assert len(data) == const.PUZZLE_LENGTH
	assert isinstance(data, str)

	data = data.encode('hex')

	puzzle = {}
	puzzle["n"] = int(data[0:128], 16)
	puzzle["Ck"] = int(data[128:256], 16)

	return puzzle



def generateRawPuzzle( masterKey ):
	"""Generates a time-lock puzzle with the given masterKey locked inside.
	Returns the puzzle as 128-byte string which is ready to be sent over the
	wire."""

	assert len(masterKey) == const.MASTER_KEY_SIZE

	riddler = TimeLockPuzzle()
	puzzle = riddler.generatePuzzle(const.MASTER_KEY_PREFIX + masterKey)

	# Convert decimal numbers to raw strings.
	rawPuzzle = bytearray()
	rawPuzzle = [util.dump(x) for x in [puzzle["n"], puzzle["Ck"]]]

	# Return single concatenated string.
	return "".join(rawPuzzle)


def looksLikePuzzle( assumedPuzzle ):
	"""Returns `True' if any of the hard-coded primes is a factor of a given `n'
	or `False' otherwise."""

	if not (len(util.dump(assumedPuzzle["n"])) == \
			len(util.dump(assumedPuzzle["Ck"])) == \
			(const.PUZZLE_MODULUS_LENGTH / 8)):
		return False

	for prime in primes.primes:
		if (assumedPuzzle["n"] % prime) == 0:
			return False
	return True


def encryptPuzzle( rawPuzzle ):
	"""Encrypts the given `rawPuzzle' with a randomly chosen and small key and
	returns the encrypted puzzle together with the nonce used for AES-CTR."""

	assert len(rawPuzzle) == const.PUZZLE_LENGTH

	log.debug("Encrypting raw %d-byte puzzle." % len(rawPuzzle))

	nonce = mycrypto.strong_random(const.PUZZLE_NONCE_LENGTH)
	cntr = Counter.new(128, initial_value=long(nonce.encode('hex'), 16))
	key = const.MIN_16BYTE_VALUE + \
			random.randint(0, (2 ** const.PUZZLE_OBFUSCATION_KEYSPACE) - 1)
	cipher = AES.new(util.dump(key), AES.MODE_CTR, counter=cntr)

	log.debug("Puzzle key=%x, nonce=%s." % (key, nonce.encode('hex')))

	return cipher.encrypt(rawPuzzle), nonce


def bruteForcePuzzle( nonce, encryptedPuzzle, callback ):
	"""Try to obtain the original puzzle by brute-forcing `encryptedPuzzle'
	using the given `nonce' for AES-CTR. When the original is found, `callback'
	is called with the locked master key as argument."""

	assert len(nonce) == const.PUZZLE_NONCE_LENGTH
	assert len(encryptedPuzzle) == const.PUZZLE_LENGTH

	# Try to obtain the puzzle by brute-forcing the n-bit key space.
	for key in xrange(2 ** const.PUZZLE_OBFUSCATION_KEYSPACE):

		cntr = Counter.new(128, initial_value=long(nonce.encode('hex'), 16))
		cipher = AES.new(util.dump(const.MIN_16BYTE_VALUE + key), \
				AES.MODE_CTR, counter=cntr)
		assumedPuzzle = extractPuzzle(cipher.decrypt(encryptedPuzzle))

		# FIXME - terminate still running processes if the puzzle was already
		# found.

		if looksLikePuzzle(assumedPuzzle):
			log.debug("Solving puzzle candidate with key=0x100...00%x." % key)
			solvePuzzleInProcess(assumedPuzzle, callback)


def solvePuzzleInProcess( puzzle, finalCallback ):
	"""Solves the given `puzzle' in a dedicated process. After the puzzle is
	unlocked, we verify whether it was the original puzzle. If it was,
	`callback' is called with the master key as argument."""

	log.debug("Attempting to unlock puzzle in dedicated process.")

	def unlockedCallback( masterKey ):
		if not (len(masterKey) == (const.MASTER_KEY_SIZE +
			len(const.MASTER_KEY_PREFIX))):
			return
		if not (const.MASTER_KEY_PREFIX in masterKey):
			log.debug("Solved a wrong puzzle, damn it!")
			return
		# Looks like we finally unlocked the original puzzle!
		finalCallback(masterKey)

	log.debug("Current working directory: %s" % os.getcwd())
	pp = processprotocol.MyProcessProtocol(puzzle, unlockedCallback)
	reactor.spawnProcess(pp, sys.executable, [sys.executable, "timelock.py"], \
		env=os.environ)


class TimeLockPuzzle:
	"""Implements time-lock puzzles as proposed by Rivest, Shamir and Wagner in
	1996. Two methods provide an interface to generate and to solve puzzles."""

	def __init__( self ):
		self.a = 2
		self.squaringsPerSec = 4000000 # Calibrated on Intel Core i7, 2.13 GHz.
		self.lockTime = const.PUZZLE_UNLOCK_TIME
		self.t = self.squaringsPerSec * self.lockTime


	def generatePuzzle( self, message, modulus=const.PUZZLE_MODULUS_LENGTH):
		"""Generates a new time-lock puzzle by locking the given message and
		using the given modulus. The new puzzle is then returned."""

		assert (len(message) * 8) < const.PUZZLE_MODULUS_LENGTH

		if (modulus % 8) != 0:
			raise ValueError("Modulus must be divisible by 8.")

		puzzle = {}

		while True:
			# Generate random primes and add `n' (= p * q) to the puzzle.
			p = number.getPrime(modulus / 2)
			q = number.getPrime(modulus / 2)
			n = p * q
			puzzle["n"] = n

			# Use phi_n as a shortcut to ``encrypt'' the message.
			phi_n = (p - 1) * (q - 1)
			e = pow(2, self.t, phi_n)
			b = pow(self.a, e, n)
			Ck = (int(message.encode("hex"), 16) + b) % n
			puzzle["Ck"] = Ck

			# Make sure that the puzzle is always of the same size.
			if len(util.dump(puzzle["n"])) == \
					len(util.dump(puzzle["Ck"])) == (modulus / 8):
				return puzzle


	def solvePuzzle( self, puzzle ):
		"""Attempts to unlock the given puzzle based on the global constants
		and the semiprime `n'. The locked master key is then returned."""

		assert len(puzzle.items()) == 2

		n, Ck = puzzle["n"], puzzle["Ck"]
		b = pow(gmpy.mpz(self.a), pow(2, self.t), n)
		masterKey = (Ck - b) % n

		return util.dump(masterKey)


# Alias class name in order to provide a more intuitive API.
new = TimeLockPuzzle


# If invoked standalone, try to solve the pickled puzzle coming over stdin.
if __name__ == '__main__':
	riddler = TimeLockPuzzle()

	puzzle = pickle.load(sys.stdin)
	assert isinstance(puzzle["n"], long) and isinstance(puzzle["Ck"], long)
	assert int(math.log(puzzle["n"], 2)) <= const.PUZZLE_MODULUS_LENGTH
	assert int(math.log(puzzle["Ck"], 2)) <= const.PUZZLE_MODULUS_LENGTH

	# Inform calling process about solved puzzle by writing to stdout.
	print riddler.solvePuzzle(puzzle)
