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
import util
from Crypto.Util import number
from Crypto.Cipher import ARC4

import const


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
