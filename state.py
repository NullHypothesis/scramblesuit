#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Provide a way to store the server's state information on disk.

The server possesses state information which should persist across runs.  This
includes key material to encrypt and authenticate session tickets, replay
tables and PRNG seeds.  This module provides methods to load, store and
generate such state information.
"""

import os
import sys
import time
import pickle
import random

import const
import replay
import mycrypto
import probdist

import obfsproxy.common.log as logging

log = logging.get_obfslogger()

def load( ):
    """
    Load the server's state object from file.

    The server's state file is loaded and the state object returned.  If no
    state file is found, a new one is created and returned.
    """

    log.info("Attempting to load the server's state file from `%s'." %
             const.SERVER_STATE_FILE)

    if not os.path.exists(const.SERVER_STATE_FILE):
        log.info("The server's state file does not exist (yet).")
        state = State()
        state.genState()
        return state

    try:
        with open(const.SERVER_STATE_FILE, 'r') as fd:
            stateObject = pickle.load(fd)
    except IOError as err:
        log.error("Error reading server state file from `%s': %s" %
                  (const.SERVER_STATE_FILE, err))
        sys.exit(1)

    return stateObject

class State( object ):

    """
    Implement a state class which stores the server's state.

    This class makes it possible to store state information on disk.  It
    provides methods to generate and write state information.
    """

    def __init__( self ):
        """
        Initialise a `State' object.
        """

        self.prngSeed = None
        self.keyCreation = None
        self.hmacKey = None
        self.aesKey = None
        self.oldHmacKey = None
        self.oldAesKey = None
        self.ticketReplay = None
        self.uniformDhReplay = None
        self.pktDist = None
        self.iatDist = None

    def genState( self ):
        """
        Populate all the local variables with values.
        """

        log.info("Generating parameters for the server's state file.")

        # PRNG seed for the client to reproduce the packet and IAT morpher.
        self.prngSeed = mycrypto.strongRandom(const.PRNG_SEED_LENGTH)

        # HMAC and AES key used to encrypt and authenticate tickets.
        self.hmacKey = mycrypto.strongRandom(const.HMAC_KEY_LENGTH)
        self.aesKey = mycrypto.strongRandom(const.AES_KEY_LENGTH)
        self.keyCreation = int(time.time())

        # The previous HMAC and AES keys.
        self.oldHmacKey = None
        self.oldAesKey = None

        # Replay dictionaries for both authentication mechanisms.
        self.ticketReplay = replay.SessionTicketTracker()
        self.uniformDhReplay = replay.UniformDHTracker()

        # Distributions for packet lengths and inter arrival times.
        prng = random.Random(self.prngSeed)
        self.pktDist = probdist.new(lambda: prng.randint(const.HDR_LENGTH,
                                                           const.MTU),
                                    seed=self.prngSeed)
        self.iatDist = probdist.new(lambda: prng.random() % 0.01,
                                    seed=self.prngSeed)

        self.writeState()

    def registerKey( self, key ):
        """
        Register the given `key' in a replay table.

        Depending on the key length, it is either added to the ticket replay
        table or the UniformDH replay table.
        """

        assert (self.ticketReplay is not None) and \
               (self.uniformDhReplay is not None)

        if len(key) == const.MASTER_KEY_LENGTH:
            self.ticketReplay.addKey(key)
            self.writeState()
        elif len(key) == const.PUBLIC_KEY_LENGTH:
            self.uniformDhReplay.addKey(key)
            self.writeState()
        else:
            log.warning("Received unknown key length of %d bytes to register "
                        "for replay attacks." % len(key))

    def writeState( self ):
        """
        Write the state object to a file using the `pickle' module.
        """

        log.debug("Writing server's state file to `%s'." %
                  const.SERVER_STATE_FILE)

        try:
            with open(const.SERVER_STATE_FILE, 'w') as fd:
                pickle.dump(self, fd)
        except IOError as err:
            log.error("Error writing state file to `%s': %s" %
                      (const.SERVER_STATE_FILE, err))
            sys.exit(1)
