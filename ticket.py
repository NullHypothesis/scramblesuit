#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
This module provides a session ticket mechanism.

The implemented mechanism is a subset of session tickets as proposed for
TLS in RFC 5077.

The format of a 112-byte ticket is:
 +------------+------------------+--------------+
 | 16-byte IV | 64-byte E(state) | 32-byte HMAC |
 +------------+------------------+--------------+

The 64-byte encrypted state contains:
 +-------------------+--------------------+--------------------+-------------+
 | 4-byte issue date | 18-byte identifier | 32-byte master key | 10-byte pad |
 +-------------------+--------------------+--------------------+-------------+
"""

import os
import time
import const
import pickle
import base64
import struct
import datetime

from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256

import obfsproxy.common.log as logging

import mycrypto
import util

log = logging.get_obfslogger()

# Length of the IV which is used for AES-CBC.
IV_LENGTH = 16

# Length of the HMAC used to authenticate the ticket.
HMAC_KEY_LENGTH = 32

# Length of the AES key used to encrypt the ticket.
AES_KEY_LENGTH = 16

# Must be a multiple of 16 bytes due to AES' block size.
IDENTIFIER = "ScrambleSuitTicket"

HMACKey = AESKey = creationTime = None


def findStoredTicket( bridge, fileName=const.TICKET_FILE ):

    assert bridge

    log.debug("Attempting to read master key and ticket from file `%s'." %
              fileName)

    if not os.path.exists(fileName):
        return None

    # Load the ticket hash table from file.
    blurb = util.readFromFile(fileName)
    if (blurb is None) or (len(blurb) == 0):
        return None
    tickets = pickle.loads(blurb)

    try:
        masterKey, ticket = tickets[bridge]
    except KeyError:
        log.info("Found no ticket for bridge `%s'." % str(bridge))
        return None

    return (masterKey, ticket)


def rotateKeys( ):
    """The keys used to encrypt and authenticate tickets are rotated
    periodically.  New keys are created but the old keys are still cached for
    the next period to validate previously issued tickets."""

    global HMACKey
    global AESKey
    global creationTime

    log.info("Attempting to rotate session ticket keys.")

    # Generate and load fresh keys.
    HMACKey = mycrypto.strong_random(HMAC_KEY_LENGTH)
    AESKey = mycrypto.strong_random(AES_KEY_LENGTH)
    creationTime = int(time.time())

    try:
        with open(const.KEY_STORE, 'w') as fd:
            pickle.dump([creationTime, HMACKey, AESKey], fd)
    except IOError as err:
        log.error("Error writing ticket key file to `%s'." % err)


def loadKeys( ):
    """Try to load the AES and HMAC key used to encrypt and authenticate
    tickets from the key store."""

    global HMACKey
    global AESKey
    global creationTime

    log.info("Attempting to read ticket keys k_S from file `%s'." %
             const.KEY_STORE)

    # If the key store does not exist (yet), it must be created.
    if not os.path.exists(const.KEY_STORE):
        rotateKeys()
        return

    try:
        with open(const.KEY_STORE, 'r') as fd:
            creationTime, HMACKey, AESKey = pickle.load(fd)
    except IOError as err:
        log.error("Error reading ticket key file from `%s'." % err)


def checkKeys( ):
    """Load the AES and the HMAC key if they are not defined yet.  If they are
    expired, rotate the keys."""

    if (HMACKey is None) or (AESKey is None):
        loadKeys()

    if (int(time.time()) - creationTime) > const.KEY_ROTATION_TIME:
        rotateKeys()


def decrypt( ticket ):
    """Verifies the validity, decrypts and finally returns the given potential
    ticket as a ProtocolState object.  If the ticket is invalid, `None' is
    returned."""

    assert (ticket is not None) and (len(ticket) == const.TICKET_LENGTH)

    global HMACKey
    global AESKey
    global creationTime

    log.debug("Attempting to decrypt and verify ticket.")

    checkKeys()

    # Verify the ticket's authenticity before decrypting.
    hmac = HMAC.new(HMACKey, ticket[0:80], digestmod=SHA256).digest()
    if hmac != ticket[80:const.TICKET_LENGTH]:
        log.debug("The ticket's HMAC is invalid.  Probably not a ticket.")
        return None

    # Decrypt the ticket to extract the state information.
    aes = AES.new(AESKey, mode=AES.MODE_CBC, IV=ticket[0:IV_LENGTH])
    plainTicket = aes.decrypt(ticket[IV_LENGTH:80])

    issueDate = struct.unpack('I', plainTicket[0:4])[0]
    identifier = plainTicket[4:22]
    masterKey = plainTicket[22:54]

    if not (identifier == IDENTIFIER):
        log.error("The ticket's HMAC is valid but the identifier is invalid.  "
                  "The ticket could be corrupt.")
        return None

    return ProtocolState(masterKey, issueDate=issueDate)


class ProtocolState( object ):
    """Describes the protocol state of a ScrambleSuit server which is part of a
    session ticket.  The state can be used to bootstrap a ScrambleSuit session
    without a UniformDH handshake."""

    def __init__( self, masterKey, issueDate=int(time.time()) ):
        self.identifier = IDENTIFIER
        self.masterKey = masterKey
        self.issueDate = issueDate
        # Pad to multiple of 16 bytes to match AES' block size.
        self.pad = "\0\0\0\0\0\0\0\0\0\0"


    def isValid( self ):
        """Returns `True' if the protocol state is valid, i.e., if the life
        time has not expired yet.  Otherwise, `False' is returned."""

        assert self.issueDate

        lifetime = int(time.time()) - self.issueDate
        if lifetime > const.SESSION_TICKET_LIFETIME:
            log.debug("The ticket expired %s ago." %
                      str(datetime.timedelta(seconds=
                      (lifetime - const.SESSION_TICKET_LIFETIME))))
            return False

        log.debug("The ticket is still valid for %s." %
                  str(datetime.timedelta(seconds=
                  (const.SESSION_TICKET_LIFETIME - lifetime))))

        return True


    def __repr__( self ):

        return struct.pack('I', self.issueDate) + self.identifier + \
                           self.masterKey + self.pad


class SessionTicket( object ):
    """Encapsulates a session ticket which can be used by the client to gain
    access to a ScrambleSuit server without conducting a UniformDH
    handshake."""

    def __init__( self, masterKey ):
        """Initialise a new session ticket which contains `masterKey'. The
        parameter `symmTicketKey' is used to encrypt the ticket and
        `hmacTicketKey' is used to authenticate the ticket when issued."""

        assert (masterKey is not None) and \
               len(masterKey) == const.MASTER_KEY_LENGTH

        checkKeys()

        # Initialisation vector for AES-CBC.
        self.IV = mycrypto.strong_random(IV_LENGTH)

        # The server's (encrypted) protocol state.
        self.state = ProtocolState(masterKey)

        # AES and HMAC keys to encrypt and authenticate the ticket.
        self.symmTicketKey = AESKey
        self.hmacTicketKey = HMACKey


    def issue( self ):
        """Encrypt and authenticate the ticket and return the result which is
        ready to be sent over the wire. In particular, the ticket name (for
        bookkeeping) as well as the actual encrypted ticket is returned."""

        self.state.issueDate = int(time.time())

        # Encrypt the protocol state.
        aes = AES.new(self.symmTicketKey, mode=AES.MODE_CBC, IV=self.IV)
        state = repr(self.state)
        assert (len(state) % AES.block_size) == 0
        cryptedState = aes.encrypt(state)

        # Authenticate the encrypted state and the IV.
        hmac = HMAC.new(self.hmacTicketKey,
                        self.IV + cryptedState, digestmod=SHA256).digest()

        finalTicket = self.IV + cryptedState + hmac
        log.debug("Returning %d-byte ticket." % len(finalTicket))

        return finalTicket


# Alias class name in order to provide a more intuitive API.
new = SessionTicket


# Give ScrambleSuit server operators a way to manually issue new session
# tickets for out-of-band distribution.
if __name__ == "__main__":

    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("ticket_file", type=str, help="The file, the newly "
                        "issued ticket is written to.")
    args = parser.parse_args()

    print "[+] Generating new session ticket."
    masterKey = mycrypto.strong_random(const.MASTER_KEY_LENGTH)
    ticketObj = SessionTicket(masterKey)
    ticket = ticketObj.issue()

    print "[+] Writing new session ticket to `%s'." % args.ticket_file
    util.writeToFile(base64.b32encode(masterKey + ticket) + '\n',
                     args.ticket_file)

    print "[+] Success."
