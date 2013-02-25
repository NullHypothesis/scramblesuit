#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Defines constant values for the ScrambleSuit protocol.
The values below are not supposed to be changed. If you don't obey, be at least
careful because things could break easily.
"""

# Key size for the AES session key and its IV in bytes.
SESSION_KEY_SIZE = IV_SIZE = 32

# Key size for the master key in bytes.
MASTER_KEY_SIZE = 32

# The maximum padding length to be appended to the puzzle in bytes.
MAX_PADDING_LENGTH = 4096

# Length of the time-lock puzzle (consisting of `n' and `Ck') in bytes.
PUZZLE_LENGTH = 128

# The length of the puzzle's modulus `n' in bits.
PUZZLE_MODULUS_LENGTH = 512

# Approximate CPU time in seconds necessary to solve the puzzle.
PUZZLE_UNLOCK_TIME = 120

# Length of the magic values in bytes.
MAGIC_LENGTH = 32

# States which are used for the protocol state machine.
ST_WAIT_FOR_TICKET = 0
ST_WAIT_FOR_PUZZLE = 1
ST_SOLVING_PUZZLE = 2
ST_WAIT_FOR_MAGIC = 3
ST_CONNECTED = 4

# Length of ScrambleSuit's header in bytes.
HDR_LENGTH = 16 + 2 + 2

# Length of the HMAC-SHA256-128 in bytes.
HMAC_LENGTH = 16

# Length of ScrambleSuit's MTU in bytes.
MTU = 1460

# Length of a session ticket in bytes.
SESSION_TICKET_LENGTH = 112

# Life time of session tickets in hours.
SESSION_TICKET_LIFETIME = 24 * 7

# The prefix prepended to the master key which is locked inside the time-lock
# puzzle. The client looks for this prefix to verify that the puzzle was
# unlocked successfully.
MASTER_KEY_PREFIX = "MasterKey="

# The protocol name which is used in log messages.
TRANSPORT_NAME = "ScrambleSuit"

# SHA256's digest size in bytes.
SHA256_DIGEST_SIZE = 32
