#!/usr/bin/env python

"""
This script generates shared secrets which can be used for ScrambleSuit.
Simply add the output of this script to your bridge's torrc.
"""

import os
import base64

sharedSecret = base64.b32encode(os.urandom(20))

print "ServerTransportOptions scramblesuit password=%s" % sharedSecret
