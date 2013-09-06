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

import mycrypto

log = logging.get_obfslogger()


def isValidHMAC( hmac1, hmac2, key ):
    """
    Compares `hmac1' and `hmac2' after HMACing them again using `key'.

    The arguments `hmac1' and `hmac2' are compared.  If they are equal, `True'
    is returned and otherwise `False'.  To prevent timing attacks, double HMAC
    verification is used meaning that the two arguments are HMACed again before
    (constant-time) string comparison.  The idea is taken from:
    https://www.isecpartners.com/blog/2011/february/double-hmac-verification.aspx
    """

    assert len(hmac1) == len(hmac2)
    assert len(key) == const.HMAC_KEY_LENGTH

    # HMAC the arguments again to prevent timing attacks.
    doubleHmac1 = mycrypto.HMAC_SHA256_128(key, hmac1)
    doubleHmac2 = mycrypto.HMAC_SHA256_128(key, hmac2)

    if doubleHmac1 != doubleHmac2:
        log.warning("The HMAC is invalid: `%s' vs. `%s'." %
                    (hmac1.encode('hex'), hmac2.encode('hex')))
        return False

    log.debug("The computed HMAC is valid.")

    return True


def locateMark( mark, payload ):
    """
    Locate the given `mark' in `payload' and return its index.

    The `mark' is placed before the HMAC of a ScrambleSuit authentication
    mechanism and makes it possible to efficiently locate the HMAC.  If the
    `mark' could not be found, `None' is returned.
    """

    index = payload.find(mark)
    if index < 0:
        log.debug("Could not find the mark just yet.")
        return None

    if (len(payload) - index - const.MARK_LENGTH) < const.HMAC_LENGTH:
        log.debug("Found the mark but the HMAC is still incomplete.")
        return None

    log.debug("Successfully located the mark.")

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
