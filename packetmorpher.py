#!/usr/bin/python
# -*- coding: utf-8 -*-

import random

import probdist
import const

class PacketMorpher( object ):
	"""Provides an interface to morph large chunks of bytes to a given target
	probability distribution. This is implemented by naively sampling the
	target probability distribution."""

	def __init__( self, dist=None ):
		"""Initialize the PacketMorpher with a discrete probability
		distribution. If none is given, a distribution is randomly
		generated."""

		self.dist = dist if dist else \
			probdist.RandProbDist(lambda: random.randint(1, const.MTU))


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
