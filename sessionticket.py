#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Implements a variant of session tickets as proposed for TLS in RFC 5077:
https://tools.ietf.org/html/rfc5077
"""

import os
import random
import time
import const

from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256

import mycrypto

NAME_LENGTH = 16

IV_LENGTH = 16

# Must be a multiple of 16 bytes due to AES' block size.
IDENTIFIER = "ScrambleSuitTicket"


class ProtocolState( object ):
	"""Describes the protocol state of a ScrambleSuit server which is part of a
	session ticket. The state can be used to bootstrap a ScrambleSuit session
	without the client unlocking the puzzle."""

	def __init__( self, masterKey ):
		self.identifier = IDENTIFIER
		#self.protocolVersion = None
		self.masterKey = masterKey
		#self.clientIdentity = None
		self.issueDate = None
		# Pad to multiple of 16 bytes due to AES' block size.
		self.pad = "\0\0\0\0"


	def __repr__( self ):

		return self.issueDate + self.identifier + self.masterKey + self.pad


class SessionTicket( object ):
	"""Encapsulates a session ticket which can be used by the client to gain
	access to a ScrambleSuit server without solving the served puzzle."""

	def __init__( self, masterKey, symmTicketKey, hmacTicketKey ):
		"""Initialize a new session ticket which contains `masterKey'. The
		parameter `symmTicketKey' is used to encrypt the ticket and
		`hmacTicketKey' is used to authenticate the ticket when issued."""

		assert len(masterKey) == len(symmTicketKey) == len(hmacTicketKey) == 16

		# The random name is used to recognize previously issued tickets.
		self.keyName = mycrypto.weak_random(NAME_LENGTH)

		# Initialization vector for AES-CBC.
		self.IV = mycrypto.strong_random(IV_LENGTH)

		# The server's actual (encrypted) protocol state.
		self.state = ProtocolState(masterKey)

		# AES and HMAC key to protect the ticket.
		self.symmTicketKey = symmTicketKey
		self.hmacTicketKey = hmacTicketKey


	def issue( self ):
		"""Encrypt and authenticate the ticket and return the result which is
		ready to be sent over the wire. In particular, the ticket name (for
		bookkeeping) as well as the actual encrypted ticket is returned."""

		self.state.issueDate = "%d" % time.time()

		# Encrypt the protocol state.
		aes = AES.new(self.symmTicketKey, mode=AES.MODE_CBC, IV=self.IV)
		state = repr(self.state)
		assert (len(state) % AES.block_size) == 0
		cryptedState = aes.encrypt(repr(self.state))

		# Authenticate ticket name, IV and the encrypted state.
		hmac = HMAC.new(self.hmacTicketKey, self.keyName + self.IV + \
				cryptedState, digestmod=SHA256).digest()

		ticket = self.keyName + self.IV + cryptedState + hmac

		return (self.keyName, ticket)


# Alias class name in order to provide a more intuitive API.
new = SessionTicket
