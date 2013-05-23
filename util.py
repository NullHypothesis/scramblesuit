#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Utility functions.
"""

import obfsproxy.common.log as logging

import const

log = logging.get_obfslogger()

def dump( n ):
	"""Converts the given number to a byte string ready to be sent over the
	wire."""

	s = '%x' % n
	if len(s) & 1:
		s = '0' + s
	return s.decode('hex')


def writeToFile( data, fileName ):

	try:
		with open(fileName, "wb") as fd:
			fd.write(data)
			fd.close()

	except IOError as e:
		pass


def readFromFile( fileName, length=-1 ):

	data = None

	log.debug("Opening `%s' for reading." % fileName)

	try:
		with open(fileName, "rb") as fd:
			data = fd.read(length)
			fd.close()

	except IOError as e:
		log.error("Could not read data from \"%s\"." % fileName)

	return data


def swap( a, b ):
	return (b, a)
