#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This module defines constant values for the ScrambleSuit protocol.

While some values can be changed, in general they should not.  If you do not
obey, be at least careful because the protocol could easily break.
"""

# Length of the HMAC used to authenticate tickets in bytes.
HMAC_KEY_LENGTH = 32

# Length of the AES key used to encrypt tickets in bytes.
AES_KEY_LENGTH = 16

# Length of the IV for AES-CBC which is used to encrypt tickets in bytes.
AES_CBC_IV_LENGTH = 16

# FIXME - Directory where long-lived information is stored.
DATA_DIRECTORY = "/tmp/"

# Divisor (in seconds) for the Unix epoch used to defend against replay
# attacks.
EPOCH_GRANULARITY = 3600

# Flags which can be set in a ScrambleSuit protocol message.
FLAG_PAYLOAD =        (1 << 0)
FLAG_NEW_TICKET =     (1 << 1)
FLAG_CONFIRM_TICKET = (1 << 2)
FLAG_PRNG_SEED =      (1 << 3)

# Length of ScrambleSuit's header in bytes.
HDR_LENGTH = 16 + 2 + 2 + 1

# Length of the HMAC-SHA256-128 in bytes.
HMAC_LENGTH = 16

# Key rotation time for session ticket keys in seconds.
KEY_ROTATION_TIME = 60 * 60 * 24 * 7

# Marker used to easily locate the HMAC authenticating handshake messages in
# bytes.
MARKER_LENGTH = 16

# The master key's length in bytes.
MASTER_KEY_LENGTH = 32

# Maximum amount of seconds, a packet is delayed due to inter arrival time
# obfuscation.
MAX_PACKET_DELAY = 0.01

# The maximum amount of padding to be appended to handshake data.
MAX_PADDING_LENGTH = 1500

# Length of ScrambleSuit's MTU in bytes.  Note that this is *not* the link MTU
# which is probably 1500.
MTU = 1448

# Maximum payload unit of a ScrambleSuit message in bytes.
MPU = MTU - HDR_LENGTH

# Length of a UniformDH public key in bytes.
PUBLIC_KEY_LENGTH = 192

# Length of the PRNG seed used to generate probability distributions in bytes.
PRNG_SEED_LENGTH = 32

# File which holds the server's state information.
SERVER_STATE_FILE = DATA_DIRECTORY + "server_state.cpickle"

# Life time of session tickets in seconds.
SESSION_TICKET_LIFETIME = 60 * 60 * 24 * 7

# SHA256's digest length in bytes.
SHA256_DIGEST_LENGTH = 32

# The length of the UniformDH shared secret in bytes.
SHARED_SECRET_LENGTH = 32

# States which are used for the protocol state machine.
ST_WAIT_FOR_AUTH = 0
ST_CONNECTED = 1

# File which holds the client's session tickets.
CLIENT_TICKET_FILE = DATA_DIRECTORY + "session_ticket.cpickle"

# Static validation string embedded in all tickets.  Must be a multiple of 16
# bytes due to AES' block size.
TICKET_IDENTIFIER = "ScrambleSuitTicket"

# Length of a session ticket in bytes.
TICKET_LENGTH = 112

# The protocol name which is used in log messages.
TRANSPORT_NAME = "ScrambleSuit"
