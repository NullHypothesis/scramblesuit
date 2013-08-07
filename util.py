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


def constCompare( val1, val2 ):
    """
    Implements (semi-)constant-time string comparison of `val1' and `val2'.

    The parameters `val1' and `val2' are compared.  If they are equal, `True'
    is returned and otherwise `False'.  The comparison is implemented in
    constant time to prevent timing-based cryptographic attacks.  However, note
    that it is *hard* to implement perfectly safe functions; even more so in
    high-level languages.

    The code is taken from:
    http://rdist.root.org/2010/01/07/timing-independent-array-comparison/
    """

    if len(val1) != len(val2):
        return False

    result = 0
    for x, y in zip(val1, val2):
        result |= ord(x) ^ ord(y)

    return result == 0


def isValidHMAC( myHMAC, existingHMAC ):
    """
    Check if the two given HMACs are equal.

    If the two given HMACs are equal, `True' is returned.  If not, a warning is
    logged and `False' is returned.
    """

    assert myHMAC and existingHMAC

    if not constCompare(myHMAC, existingHMAC):
        log.warning("The HMAC is invalid (got `%s' but expected `%s')." %
                    (existingHMAC.encode('hex'), myHMAC.encode('hex')))
        return False

    log.debug("The computed HMAC is valid.")

    return True


def locateMarker( marker, payload ):
    """
    Locate the given `marker' in `payload' and return its index.

    The `marker' is placed before the HMAC of a ScrambleSuit authentication
    mechanism and makes it possible to efficiently locate the HMAC.  If the
    `marker' could not be found, `None' is returned.
    """

    index = payload.find(marker)
    if index < 0:
        log.debug("Could not find the marker just yet.")
        return None

    if (len(payload) - index - const.MARKER_LENGTH) < const.HMAC_LENGTH:
        log.debug("Found the marker but the HMAC is still incomplete.")
        return None

    log.debug("Successfully located the marker.")

    return index


def getEpoch( ):
    """
    Return the Unix epoch divided by a constant as string.

    This function returns a coarse-grained version of the Unix epoch.  The
    seconds passed since the epoch are divided by the constant
    `EPOCH_GRANULARITY'.
    """

    return str(int(time.time()) / const.EPOCH_GRANULARITY)


def writeToFile( data, fileName ):
    """
    Writes the given `data' to the file specified by `fileName'.

    If an error occurs, the function logs an error message but does not throw
    an exception or return an error code.
    """

    log.debug("Opening `%s' for writing." % fileName)

    try:
        with open(fileName, "wb") as desc:
            desc.write(data)

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
        with open(fileName, "rb") as desc:
            data = desc.read(length)

    except IOError as err:
        log.error("Error reading from `%s': %s." % (fileName, err))

    return data


def swap( var1, var2 ):
    """
    Returns `var1' and `var2' in reverse order, i.e., `var2' and `var1'.
    """

    return (var2, var1)
