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
    """Converts the given number `n' to a byte string.

    The returned byte string is ready to be sent over the wire.
    """

    s = '%x' % n
    if len(s) & 1:
        s = '0' + s
    return s.decode('hex')


def writeToFile( data, fileName ):
    """
    Writes the given `data' to the file specified by `fileName'.

    If an error occurs, the function logs an error message but does not throw
    an exception or return an error code.
    """

    log.debug("Opening `%s' for writing." % fileName)

    try:
        with open(fileName, "wb") as fd:
            fd.write(data)

    except IOError as err:
        log.error("Error writing to `%s': %s." % (fileName, err))


def readFromFile( fileName, length=-1 ):
    """
    Read `length' amount of bytes from the given `fileName' 

    If `length' equals -1 (the default), the entire file is read and the
    content returned.  If an error occurs, the function logs an error message
    but does not throw an exception or return an error code.
    """

    data = None

    log.debug("Opening `%s' for reading." % fileName)

    try:
        with open(fileName, "rb") as fd:
            data = fd.read(length)

    except IOError as err:
        log.error("Error reading from `%s': %s." % (fileName, err))

    return data


def swap( a, b ):
    """
    Returns `a' and `b' in reverse order, i.e., `b' and `a'.
    """

    return (b, a)
