#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Utility functions.
"""

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


def swap( a, b ):
	return (b, a)
