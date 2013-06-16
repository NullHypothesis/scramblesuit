#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This module implements several commonly used utility functions.

The implemented functions can be used to swap variables, write and read data
from files and to convert a number to raw text.
"""

import obfsproxy.common.log as logging

import time
import const

log = logging.get_obfslogger()

def getEpoch( ):
    """
    Return the Unix epoch divided by a constant as string.

    This function returns a coarse-grained version of the Unix epoch.  The
    seconds passed since the epoch are divided by the constant
    `EPOCH_GRANULARITY'.
    """

    return str(int(time.time()) / const.EPOCH_GRANULARITY)

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
