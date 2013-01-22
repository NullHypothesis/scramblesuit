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



def dump( n ):
	"""Converts the given number to a byte string ready to be sent over the
	wire."""

	s = '%x' % n
	if len(s) & 1:
		s = '0' + s
	return s.decode('hex')


def extractPuzzleFromBlurb( blurb ):
	"""Extracts and returns a time-lock puzzle out of the given blurb."""

	assert(len(blurb) == 192)

	blurb = blurb.encode('hex')

	puzzle = {}
	puzzle["n"] =  int(blurb[0:128],   16)
	puzzle["a"] =  int(blurb[128:256], 16)
	puzzle["Cm"] = int(blurb[256:384], 16)

	return puzzle


class TimeLockPuzzle:
	"""TimeLockPuzzle implements a time-lock cryptographic puzzle as proposed
	by Rivest, Shamir and Wagner."""

	def __init__( self ):
		self.squaringsPerSec = 4000000 # Calibrated on Intel Core i7, 2.13 GHz.
		#self.squaringsPerSec = 10 # Calibrated on Intel Core i7, 2.13 GHz.
		self.lockTime = 3 # TODO
		self.t = self.squaringsPerSec * self.lockTime


	# Generate a new time-lock puzzle for the client to solve. The modulus
	# (in bits) should be small to not waste too many of the bridge's CPU
	# cycles but still large enough to be significantly harder to factor
	# than the puzzle to solve. Otherwise it would become the weakest link.
	def generatePuzzle( self, message, modulus=512):
		"""Generates and returns the time-lock puzzle."""

		puzzle = {}

		while True:
			# Generate random primes and add `n' (= p * q) to the puzzle.
			p = number.getPrime(modulus / 2)
			q = number.getPrime(modulus / 2)
			n = p * q
			puzzle["n"] = n

			# Generate random `a' and add it to the puzzle.
			a = random.randint(1, n)
			puzzle["a"] = a

			# Use phi_n as a shortcut to ``encrypt'' the message.
			phi_n = (p - 1) * (q - 1)
			e = pow(2, self.t, phi_n)
			b = pow(a, e, n)
			Cm = (int(message.encode("hex"), 16) + b) % n
			puzzle["Cm"] = Cm

			# Make sure that the puzzle is always of the same size.
			if len(dump(puzzle["n"])) == 64 and \
				len(dump(puzzle["a"])) == 64 and \
				len(dump(puzzle["Cm"])) == 64:
				break

		return puzzle


	def solvePuzzle( self, puzzle ):
		"""Solves the time-lock puzzle and returns the decrypted message."""

		n, a, Cm = puzzle["n"], puzzle["a"], puzzle["Cm"]

		# Note that there are faster ways to do modular squaring, such as a
		# pure C implementation or FPGAs!
		b = pow(gmpy.mpz(a), pow(2, self.t), n)

		# Extract the message.
		M = (Cm - b) % n

		return dump(M)

# Alias class name in order to provide a more intuitive API.
new = TimeLockPuzzle

# If invoked standalone, try to solve the pickled puzzle coming over stdin.
if __name__ == '__main__':
	tl = TimeLockPuzzle()

	# Load pickled puzzle from stdin.
	puzzle = pickle.load(sys.stdin)

	# Inform calling process about solved puzzle by writing to stdout.
	print tl.solvePuzzle(puzzle)
