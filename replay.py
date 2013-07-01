#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This module implements a mechanism to protect against replay attacks.

The replay protection mechanism is based on a dictionary which caches
previously observed keys.  The dictionaries can be extended and queried.  A
pruning mechanism deletes expired keys from the dictionary.
"""

import time
import pickle

import const

import obfsproxy.common.log as logging

log = logging.get_obfslogger()


class Tracker( object ):

    """
    Implement methods to keep track of replayed keys.

    This class provides methods to add new keys (elements), check whether keys
    have been observed before and to prune the lookup table.
    """

    def __init__( self ):
        """
        Initialise a `Tracker' object.
        """

        self.table = dict()

    def addElement( self, element ):
        """
        Add the given `element' to the lookup table.
        """

        if self.isPresent(element):
            raise LookupError("Element already present in table.")

        self.table[element] = int(time.time())

    def isPresent( self, element ):
        """
        Check if the given `element' is already present in the lookup table.
        """

        log.debug("Looking for existing element in size-%d lookup table." %
                  len(self.table))

        # Prune the replay table before checking for values.
        self.prune()

        return (element in self.table)

    def prune( self ):
        """
        Delete expired elements from the lookup table.
        """

        log.debug("Pruning the replay table.")

        deleteList = []
        now = int(time.time())

        for element in self.table.iterkeys():
            if (now - self.table[element]) > const.EPOCH_GRANULARITY:
                log.debug("Deleting expired element.")
                deleteList.append(element)

        # We can't delete from a dictionary while iterating over it; therefore
        # this construct.
        for elem in deleteList:
            del self.table[elem]


class UniformDHTracker( Tracker ):

    """
    Extends the `Tracker' class with an `addKey()' method for UniformDH.
    """

    def addKey( self, key ):
        """
        Add the given UniformDH public key `key' to the lookup table.
        """

        log.debug("Caching UniformDH public key.")

        self.addElement(key)


class SessionTicketTracker( Tracker ):

    """
    Extends the `Tracker' class with an `addKey()' method for session tickets.
    """

    def addKey( self, key ):
        """
        Add the given session ticket master key `key' to the lookup table.
        """

        log.debug("Caching session ticket master key.")

        self.addElement(key)
