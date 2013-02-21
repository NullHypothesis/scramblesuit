#!/usr/bin/env python
# -*- coding: utf-8 -*-

from twisted.internet import protocol
import pickle

import obfsproxy.common.log as logging

log = logging.get_obfslogger()

class MyProcessProtocol( protocol.ProcessProtocol ):
	"""Used to communicate with the time-lock solver which is an external
	python process. This class is able to send a puzzle to the process and
	retrieve the result."""


	def __init__( self, puzzle, callback ):

		log.debug("Initializing process protocol.")
		self.puzzle = puzzle
		self.callback = callback


	def connectionMade( self ):
		"""Writes the pickled time-lock puzzle to the external processes
		stdin."""

		log.debug("Handing pickled time-lock puzzle to external process.")
		pickle.dump(self.puzzle, self.transport)
		self.transport.closeStdin()


	def outReceived( self, data ):
		"""Reads the content of the unlocked puzzle from the external processes
		stdout. Afterwards, the result is delivered using a callback."""

		log.debug("Read unlocked message from the external process.")
		self.callback(data.strip())
