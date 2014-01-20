#!/bin/bash

# This command starts an obfsproxy instance which listens for SOCKS connections
# on localhost:50001.  Incoming SOCKS data is then forwarded to the
# ScrambleSuit server running on localhost:50000.  Persistent data (the
# client's session ticket) is stored in /tmp/scramblesuit-client.

python /usr/local/bin/obfsproxy \
	--log-min-severity=debug \
	--data-dir=/tmp/scramblesuit-client \
	scramblesuit \
	--password=BANANASAPPLESCOCONUTSPEACHESEGGS  \
	--dest 127.0.0.1:50000 \
	client 127.0.0.1:50001
