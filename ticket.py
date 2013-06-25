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
import random
import datetime

from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from twisted.internet.address import IPv4Address

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


def createTicketMessage( rawTicket, HMACKey ):
    """
    Create and return a ready-to-be-sent ticket authentication message.

    Pseudo-random padding and a marker are added to `rawTicket' and the result
    is then authenticated using `HMACKey' as key for a HMAC.  The resulting
    authentication message is then returned.
    """

    # Subtract the length of the ticket to make the handshake on
    # average as long as a UniformDH handshake message.
    padding = mycrypto.weakRandom(random.randint(0,
                                   const.MAX_PADDING_LENGTH -
                                   const.TICKET_LENGTH))

    marker = mycrypto.HMAC_SHA256_128(HMACKey, HMACKey + rawTicket)

    hmac = mycrypto.HMAC_SHA256_128(HMACKey, rawTicket + padding +
                                    marker + util.getEpoch())

    return rawTicket + padding + marker + hmac


def issueTicketAndKey( ):
    """
    Issues a new session ticket and returns it appended to the master key.

    The returned ticket and key are ready to be put into a protocol message.
    """

    # Issue a new session ticket for the client.
    log.info("Issuing new session ticket and master key.")
    masterKey = mycrypto.strongRandom(const.MASTER_KEY_LENGTH)
    newTicket = (SessionTicket(masterKey)).issue()

    return masterKey + newTicket


def storeNewTicket( masterKey, ticket, bridge ):
    """
    Store a new session ticket and the according master key for future use.

    The given data is pickled and stored in the global ticket dictionary.  If
    there already is a ticket for the given `bridge', it is overwritten.
    """

    assert len(masterKey) == const.MASTER_KEY_LENGTH
    assert len(ticket) == const.TICKET_LENGTH

    log.debug("Storing newly received ticket in `%s'." % const.TICKET_FILE)

    # Add a new (key, ticket) tuple with the given bridge as hash key.
    tickets = dict()
    content = util.readFromFile(const.TICKET_FILE)
    if (content is not None) and (len(content) > 0):
        tickets = pickle.loads(content)

    tickets[bridge] = (masterKey, ticket)
    util.writeToFile(pickle.dumps(tickets), const.TICKET_FILE)


def findStoredTicket( bridge, fileName=const.TICKET_FILE ):
    """
    Retrieve a previously stored ticket from the ticket dictionary.

    The global ticket dictionary is loaded and the given `bridge' is used to
    look up the ticket and the master key.  If the ticket dictionary does not
    exist (yet) or the ticket data could not be found, `None' is returned.
    """

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
    """
    Rotate the keys used to encrypt and authenticate session tickets.

    After new keys (an AES and a HMAC key) were created, the old keys are still
    kept for a period of seven days to verify (but not to issue) session
    tickets issues by the old keys.
    """

    global HMACKey
    global AESKey
    global creationTime

    log.info("Attempting to rotate session ticket keys.")

    # Generate and load fresh keys.
    HMACKey = mycrypto.strongRandom(HMAC_KEY_LENGTH)
    AESKey = mycrypto.strongRandom(AES_KEY_LENGTH)
    creationTime = int(time.time())

    try:
        with open(const.KEY_STORE, 'w') as fd:
            pickle.dump([creationTime, HMACKey, AESKey], fd)
    except IOError as err:
        log.error("Error writing ticket key file to `%s'." % err)


def loadKeys( ):
    """
    Load the keys used to encrypt and authenticate session tickets.

    The keys are loaded from file and stored in global variables so they can be
    accessed from different functions.
    """

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
    """
    Check whether the encryption and authentication keys are defined and valid.

    If the keys are not defined, they are loaded from file by calling
    `loadKeys()'.  If they are expired and no longer valid, the keys are
    rotated by calling `rotateKeys()'.
    """

    if (HMACKey is None) or (AESKey is None):
        loadKeys()

    if (int(time.time()) - creationTime) > const.KEY_ROTATION_TIME:
        rotateKeys()


def decrypt( ticket ):
    """
    Decrypts, verifies and returns the given `ticket'.

    First, the HMAC over the ticket is verified.  If it is valid, the ticket is
    decrypted.  Finally, a `ProtocolState()' object containing the master key
    and the ticket's issue date is returned.  If any of these steps fail,
    `None' is returned.
    """

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

    """
    Defines a ScrambleSuit protocol state contained in a session ticket.

    A protocol state is essentially a master key which can then be used by the
    server to derive session keys.  Besides, a state object contains an issue
    date which specifies the expiry date of a ticket.  This class contains
    methods to check the expiry status of a ticket and to dump it in its raw
    form.
    """

    def __init__( self, masterKey, issueDate=int(time.time()) ):
        """
        The constructor of the `ProtocolState' class.

        The four class variables are initialised.
        """

        self.identifier = IDENTIFIER
        self.masterKey = masterKey
        self.issueDate = issueDate
        # Pad to multiple of 16 bytes to match AES' block size.
        self.pad = "\0\0\0\0\0\0\0\0\0\0"

    def isValid( self ):
        """
        Verifies the expiry date of the object's issue date.

        If the expiry date is not yet reached and the protocol state is still
        valid, `True' is returned.  If the protocol state has expired, `False'
        is returned.
        """

        assert self.issueDate

        lifetime = int(time.time()) - self.issueDate
        if lifetime > const.SESSION_TICKET_LIFETIME:
            log.debug("The ticket is invalid and expired %s ago." %
                      str(datetime.timedelta(seconds=
                      (lifetime - const.SESSION_TICKET_LIFETIME))))
            return False

        log.debug("The ticket is still valid for %s." %
                  str(datetime.timedelta(seconds=
                  (const.SESSION_TICKET_LIFETIME - lifetime))))
        return True

    def __repr__( self ):
        """
        Return a raw string representation of the object's protocol state.

        The length of the returned representation is exactly 64 bytes; a
        multiple of AES' 16-byte block size.  That makes it suitable to be
        encrypted using AES-CBC.
        """

        return struct.pack('I', self.issueDate) + self.identifier + \
                           self.masterKey + self.pad


class SessionTicket( object ):

    """
    Encrypts and authenticates an encapsulated `ProtocolState()' object.

    This class implements a session ticket which can be redeemed by clients.
    The class contains methods to initialise and issue session tickets.
    """

    def __init__( self, masterKey ):
        """
        The constructor of the `SessionTicket()' class.

        The class variables are initialised and the validity of the symmetric
        keys for the session tickets is checked.
        """

        assert (masterKey is not None) and \
               len(masterKey) == const.MASTER_KEY_LENGTH

        checkKeys()

        # Initialisation vector for AES-CBC.
        self.IV = mycrypto.strongRandom(IV_LENGTH)

        # The server's (encrypted) protocol state.
        self.state = ProtocolState(masterKey)

        # AES and HMAC keys to encrypt and authenticate the ticket.
        self.symmTicketKey = AESKey
        self.hmacTicketKey = HMACKey

    def issue( self ):
        """
        Returns a ready-to-use session ticket after prior initialisation.

        After the `SessionTicket()' class was initialised with a master key,
        this method encrypts and authenticates the protocol state and returns
        the final result which is ready to be sent over the wire.
        """

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
    parser.add_argument("ip_addr", type=str, help="The IPv4 address of the "
                        "%s server." % const.TRANSPORT_NAME)
    parser.add_argument("tcp_port", type=int, help="The TCP port of the %s "
                        "server." % const.TRANSPORT_NAME)
    parser.add_argument("ticket_file", type=str, help="The file, the newly "
                        "issued ticket is written to.")
    args = parser.parse_args()

    print "[+] Generating new session ticket."
    masterKey = mycrypto.strongRandom(const.MASTER_KEY_LENGTH)
    ticket = SessionTicket(masterKey).issue()

    print "[+] Writing new session ticket to `%s'." % args.ticket_file
    tickets = dict()
    server = IPv4Address('TCP', args.ip_addr, args.tcp_port)
    tickets[server] = (masterKey, ticket)

    util.writeToFile(pickle.dumps(tickets), args.ticket_file)

    print "[+] Success."
