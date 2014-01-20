#!/bin/bash

# This command starts an obfsproxy instance which is listening on
# localhost:50000 for incoming ScrambleSuit connections.  The incoming data is
# then deobfuscated and forwarded to localhost:1234 which could run a simple
# echo service.  Persistent data (the server's state) is stored in
# /tmp/scramblesuit-server.

python /usr/local/bin/obfsproxy \
	--log-min-severity=debug \
	--data-dir=/tmp/scramblesuit-server \
	scramblesuit \
	--password=BANANASAPPLESCOCONUTSPEACHESEGGS \
	--dest 127.0.0.1:1234 \
	server 127.0.0.1:50000
