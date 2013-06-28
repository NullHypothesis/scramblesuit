#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
This module provides code to generate and sample probability distributions.

The class RandProbDist provides an interface to randomly generate probability
distributions.  Random samples can then be drawn from these distributions.
"""

import random

import obfsproxy.common.log as logging

log = logging.get_obfslogger()


class RandProbDist:

    """
    Provides code to generate, sample and dump probability distributions.
    """

    def __init__( self, genSingleton, seed=None ):
        """
        Initialise a discrete probability distribution.

        The parameter `genSingleton' is expected to be a function which yields
        singletons for the probability distribution.  The optional `seed' can
        be used to seed the PRNG.
        """

        # Minimum and maximum amount of distinct bins for the distribution.
        self.MIN_BINS = 1
        self.MAX_BINS = 100

        self.prng = random if (seed is None) else srandom.Random(seed)

        self.sampleList = []
        self.dist = self._genDistribution(genSingleton)
        self.dumpDistribution()

    def _genDistribution( self, genSingleton ):
        """
        Generate a discrete probability distribution.

        The parameter `genSingleton' is a function which is used to generate
        singletons for the probability distribution.
        """

        dist = {}

        # Amount of distinct bins, i.e., packet lengths or inter arrival times.
        bins = self.prng.randint(self.MIN_BINS, self.MAX_BINS)

        # Cumulative probability of all bins.
        cumulProb = 0
        flatness = self.prng.randint(1, 3)

        for b in xrange(bins):
            p = self.prng.uniform(0, (1 - cumulProb) / float(flatness))
            cumulProb += p
            singleton = genSingleton()

            dist[singleton] = p
            self.sampleList.append((cumulProb, singleton,))

        dist[genSingleton()] = (1 - cumulProb)

        return dist

    def dumpDistribution( self ):
        """
        Dump the probability distribution using the logging object.

        Only probabilities > 0.01 are dumped.
        """

        log.debug("Dumping probability distribution.")

        for singleton in self.dist.iterkeys():
            # We are not interested in tiny probabilities.
            if self.dist[singleton] > 0.01:
                log.debug("P(%s) = %.3f" %
                          (str(singleton), self.dist[singleton]))

    def randomSample( self ):
        """
        Draw and return a random sample from the probability distribution.
        """

        assert len(self.sampleList) > 0

        CUM_PROB = 0
        SINGLETON = 1

        r = self.prng.random()

        for pair in self.sampleList:
            if r <= pair[CUM_PROB]:
                return pair[SINGLETON]

        return self.sampleList[-1][SINGLETON]

# Alias class name in order to provide a more intuitive API.
new = RandProbDist
