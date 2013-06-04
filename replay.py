#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import pickle

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
		# TODO - load the database if it's not loaded already.
		log.debug("Looking for existing HMAC in size-%d dictionary." % \
				len(self.table)) 

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
		log.debug("Pruning the lookup table.")

		now = int(time.time())
		for element in self.table.iterkeys():
			if (now - self.table[element]) > const.EPOCH_GRANULARITY: # TODO no
				log.debug("Deleting element from table.")
				del self.table[element]


class UniformDHTracker( Tracker ):

	def addHMAC( self, hmac ):
		"""Add a UniformDH HMAC to the lookup table."""
		log.debug("Caching UniformDH HMAC.")

		self.addElement(hmac)


class SessionTicketTracker( Tracker ):

	def addHMAC( self, hmac ):
		"""Add a session ticket HMAC to the lookup table."""
		log.debug("Caching session ticket HMAC.")

		self.addElement(hmac)


# Both replay trackers must be shared by different scramblesuit instances.  As
# a result, they should be seen as singletons.
UniformDH = UniformDHTracker()
SessionTicket = SessionTicketTracker()
