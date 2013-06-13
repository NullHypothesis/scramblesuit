#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This module implements a mechanism to protect against replay attacks.

The replay protection mechanism is based on a dictionary which caches
previously observed keys.  The dictionaries can be extended, queried as well as
written to and read from disk.  A pruning mechanism deletes expired keys from
the dictionary.
"""

import time
import pickle

import const

import obfsproxy.common.log as logging

log = logging.get_obfslogger()


class Tracker( object ):

    def __init__( self ):
        """Initialise the Tracker() object."""
        self.table = dict()

    def addElement( self, element ):
        """Add an element to the lookup table."""
        if self.isPresent(element):
            raise LookupError("Element already present in table.")

        self.table[element] = int(time.time())

    def isPresent( self, element ):
        """Check if an element is already present in the lookup table."""
        log.debug("Looking for existing HMAC in size-%d dictionary." % \
                len(self.table)) 

        # Prune the replay table before checking for values.
        self.prune()

        return (element in self.table)

    def saveToDisk( self, fileName ):
        """Save the lookup table to disk."""
        try:
            with open(fileName, "w") as fd:
                pickle.dump(self.table, fd)
                fd.close()
        except IOError as e:
            log.error("Error saving replay table to file `%s': %s" % \
                    (fileName, e))

    def loadFromDisk( self, fileName ):
        """Load the lookup table from the disk."""
        try:
            with open(fileName, "r") as fd:
                self.table = pickle.load(fd)
                fd.close()
        except IOError as e:
            log.error("Error opening replay table from file `%s': %s." % \
                    (fileName, e))

    def prune( self ):
        """Delete expired elements from the table."""
        log.debug("Pruning the replay table.")

        deleteList = []

        now = int(time.time())
        for element in self.table.iterkeys():
            if (now - self.table[element]) > const.EPOCH_GRANULARITY:
                log.debug("Deleting expired HMAC.")
                deleteList.append(element)

        for elem in deleteList:
            del self.table[elem]


class UniformDHTracker( Tracker ):

    def addKey( self, hmac ):
        """Add a UniformDH HMAC to the lookup table."""
        log.debug("Caching UniformDH HMAC.")

        self.addElement(hmac)
        self.saveToDisk(const.UNIFORMDH_REPLAY_FILE)


class SessionTicketTracker( Tracker ):

    def addKey( self, hmac ):
        """Add a session ticket HMAC to the lookup table."""
        log.debug("Caching session ticket HMAC.")

        self.addElement(hmac)
        self.saveToDisk(const.TICKET_REPLAY_FILE)


# Both replay trackers must be shared by different scramblesuit instances.  As
# a result, they should be seen as singletons.
UniformDH = UniformDHTracker()
SessionTicket = SessionTicketTracker()
