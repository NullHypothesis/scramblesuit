#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Utility functions.
"""

def writeToFile( data, fileName ):

	try:
		with open(fileName, "wb") as fd:
			fd.write(data)
			fd.close()
	except IOError as e:
		pass


def swap( a, b ):
	return (b, a)
