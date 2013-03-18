#!/usr/bin/python
# -*- coding: utf-8 -*-

""" This module provides code to deal with probability distribution. """

import obfsproxy.common.log as logging

import random

log = logging.get_obfslogger()


class RandProbDist:
	"""Provides code to randomly generate and sample discrete probability
	distributions."""

	def __init__( self, genSingleton ):
		"""`genSingleton' is a function which returns a singleton for the
		probability distribution."""

		self.MIN_BINS = 1
		self.MAX_BINS = 100
		self.genSingleton = genSingleton
		self.sampleList = []
		self.dist = self._generateDistribution()

		log.debug("Packet size distribution:")
		for key in self.dist.keys():
			log.debug("%d: %f%%" % (key, self.dist[key]))


	def _generateDistribution( self ):
		"""Generates a random probability distribution."""

		dist = {}

		# Amount of distinct bins (e.g. packet sizes).
		bins = random.randint(self.MIN_BINS, self.MAX_BINS)
		cum_p = 0
		flatness = random.randint(1, 3)

		for b in xrange(bins - 1):
			p = random.uniform(0, (1 - cum_p) / float(flatness))
			cum_p += p
			singleton = self.genSingleton()
			dist[singleton] = p
			self.sampleList.append((cum_p, singleton,))

		dist[self.genSingleton()] = (1 - cum_p)

		return dist


	def randomSample( self ):
		"""Randomly samples the generated probability distribution."""

		# FIXME - this assertion sometimes fails.
		assert(len(self.sampleList) > 0)

		CUM_PROB = 0
		SINGLETON = 1

		r = random.random()

		for pair in self.sampleList:
			if r <= pair[CUM_PROB]:
				return pair[SINGLETON]

		return self.sampleList[-1][SINGLETON]
