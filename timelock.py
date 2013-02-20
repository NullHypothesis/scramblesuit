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
import random
import pickle
import struct
from Crypto.Util import number
from Crypto.Cipher import ARC4

import const


def dump( n ):
	"""Converts the given number to a byte string ready to be sent over the
	wire."""

	s = '%x' % n
	if len(s) & 1:
		s = '0' + s
	return s.decode('hex')


def extractPuzzleFromBlurb( blurb ):
	"""Extracts and returns a time-lock puzzle out of the given blurb."""

	assert len(blurb) == const.PUZZLE_LENGTH
	assert isinstance(blurb, str)

	blurb = blurb.encode('hex')

	puzzle = {}
	puzzle["n"] = int(blurb[0:128], 16)
	puzzle["Ck"] = int(blurb[128:256], 16)

	return puzzle


def getPuzzle( masterSecret ):
	"""Generates the time-lock puzzle for the client to solve. This will
	yield the symmetric session key."""

	assert len(masterSecret) == const.MASTER_SECRET_SIZE

	# Create puzzle which ``locks'' the shared session key.
	riddler = TimeLockPuzzle()
	puzzle = riddler.generatePuzzle(const.MASTER_KEY_PREFIX + masterSecret)

	# Convert base 10 numbers to raw strings.
	rawPuzzle = bytearray()
	rawPuzzle = [dump(x) for x in [puzzle["n"], puzzle["Ck"]]]

	# Return single concatenated string.
	return reduce(lambda x, y: x + y, rawPuzzle)


class TimeLockPuzzle:
	"""TimeLockPuzzle implements a time-lock cryptographic puzzle as proposed
	by Rivest, Shamir and Wagner."""

	def __init__( self ):
		self.a = 2
		self.squaringsPerSec = 4000000 # Calibrated on Intel Core i7, 2.13 GHz.
		#self.squaringsPerSec = 10 # Calibrated on Intel Core i7, 2.13 GHz.
		self.lockTime = 10 # TODO
		self.t = self.squaringsPerSec * self.lockTime


	# Generate a new time-lock puzzle for the client to solve. The modulus
	# (in bits) should be small to not waste too many of the bridge's CPU
	# cycles but still large enough to be significantly harder to factor
	# than the puzzle to solve. Otherwise it would become the weakest link.
	def generatePuzzle( self, message, modulus=const.PUZZLE_MODULUS_LENGTH):
		"""Generates and returns the time-lock puzzle."""

		assert (len(message) * 8) < const.PUZZLE_MODULUS_LENGTH

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
			if len(dump(puzzle["n"])) == 64 and len(dump(puzzle["Ck"])) == 64:
				break

		return puzzle


	def solvePuzzle( self, puzzle ):
		"""Solves the time-lock puzzle and returns the decrypted message."""

		assert len(puzzle.items()) == 2

		n, Ck = puzzle["n"], puzzle["Ck"]

		# Note that there are faster ways to do modular squaring, such as a
		# pure C implementation or FPGAs!
		b = pow(gmpy.mpz(self.a), pow(2, self.t), n)

		masterKey = (Ck - b) % n

		return dump(masterKey)

# Alias class name in order to provide a more intuitive API.
new = TimeLockPuzzle

# If invoked standalone, try to solve the pickled puzzle coming over stdin.
if __name__ == '__main__':
	tl = TimeLockPuzzle()

	# Load pickled puzzle from stdin.
	puzzle = pickle.load(sys.stdin)

	# Inform calling process about solved puzzle by writing to stdout.
	print tl.solvePuzzle(puzzle)
