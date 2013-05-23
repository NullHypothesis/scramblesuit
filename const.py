#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Defines constant values for the ScrambleSuit protocol.
The values below are not supposed to be changed.  If you don't obey, be at
least careful because things could break easily.
"""

# FIXME - Directory where long-lived information is stored.
DATA_DIRECTORY = "/tmp/"

# Divisor (in seconds) for the UNIX epoch used to defend against replay
# attacks.
EPOCH_GRANULARITY = 3600

# Flags which can be set in a ScrambleSuit protocol message.
FLAG_PAYLOAD = 1
FLAG_NEW_TICKET = 2
FLAG_CONFIRM_TICKET = 4

# Length of ScrambleSuit's header in bytes.
HDR_LENGTH = 16 + 2 + 2 + 1

# Length of the HMAC-SHA256-128 in bytes.
HMAC_LENGTH = 16

# Key rotation time for session ticket keys in seconds.
KEY_ROTATION_TIME = 60 * 60 * 24 * 7

# File where session ticket keys are stored.
KEY_STORE = DATA_DIRECTORY + "ticket_keys.bin"

# Magic value used to easily locate the HMAC authenticating handshake messages
# in bytes.
MAGIC_LENGTH = 16

# Key size for the master key in bytes.
MASTER_KEY_SIZE = 32

# The maximum padding length to be appended to the puzzle in bytes.
MAX_PADDING_LENGTH = 4096

# Length of ScrambleSuit's MTU in bytes.
MTU = 1460

# Maximum payload unit of a ScrambleSuit message in bytes.
MPU = MTU - HDR_LENGTH

# Length of a UniformDH public key.
PUBLIC_KEY_LENGTH = 192

# Life time of session tickets in seconds.
SESSION_TICKET_LIFETIME = 60 * 60 * 24 * 7

# SHA256's digest size in bytes.
SHA256_DIGEST_SIZE = 32

# The length of the UniformDH shared secret in bytes.
SHARED_SECRET_LENGTH = 32

# States which are used for the protocol state machine.
ST_WAIT_FOR_AUTH = 0
ST_CONNECTED = 1

# File which holds our session ticket.
# FIXME - multiple session tickets for multiple servers must be supported.
TICKET_FILE = DATA_DIRECTORY + "session_ticket.bin"

# Length of a session ticket in bytes.
TICKET_LENGTH = 112

# The protocol name which is used in log messages.
TRANSPORT_NAME = "ScrambleSuit"
