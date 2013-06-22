#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
The scramblesuit module implements the ScrambleSuit obfuscation protocol.

The paper discussing the design and evaluation of the ScrambleSuit pluggable
transport protocol is available here:
http://www.cs.kau.se/philwint/scramblesuit/
"""

from twisted.internet import error
from twisted.internet import reactor

import obfsproxy.transports.base as base
import obfsproxy.common.serialize as pack
import obfsproxy.common.log as logging
import obfsproxy.transports.obfs3_dh as obfs3_dh

import os
import random
import base64

import probdist
import mycrypto
import message
import const
import util
import packetmorpher
import ticket
import replay
import uniformdh


log = logging.get_obfslogger()


class ScrambleSuitTransport( base.BaseTransport ):

    def __init__( self ):

        log.warning("\n+++ Note that ScrambleSuit is still under "
                    "development and is NOT safe for practical use. +++\n")

        log.info("Initialising %s." % const.TRANSPORT_NAME)

        # Initialise the protocol's state machine.
        log.debug("Switching to state ST_WAIT_FOR_AUTH.")
        self.state = const.ST_WAIT_FOR_AUTH

        # UniformDH object.
        self.dh = None

        # Buffers for incoming and outgoing data.
        self.sendBuf = self.recvBuf = ""

        # Caches the outgoing data before written to the wire.
        self.choppedPieces = []

        # AES instances for incoming and outgoing data.
        self.sendCrypter = mycrypto.PayloadCrypter()
        self.recvCrypter = mycrypto.PayloadCrypter()

        # Packet morpher to modify the protocol's packet length distribution.
        self.pktMorpher =  packetmorpher.PacketMorpher()

        # Inter arrival time morpher to obfuscate inter arrival times.
        self.iatMorpher = probdist.RandProbDist(lambda: random.random() % 0.01)

        # `True' if the client used a session ticket, `False' otherwise.
        self.redeemedTicket = None

        # `True' if the ticket is already decrypted but not yet authenticated.
        self.decryptedTicket = None

        # Cache the master key so it can later be added to the replay table.
        self.ticketReplayCache = None

        # Shared secret k_B which is only used for UniformDH.
        if not hasattr(self, 'uniformDHSecret'):
            self.uniformDHSecret = None
        if self.uniformDHSecret:
            log.info("UniformDH shared secret: %s." % self.uniformDHSecret)
            self.uniformdh = uniformdh.new(self.uniformDHSecret,
                                           self.weAreServer)

        # Path to a file which contains a master key and the according ticket.
        if not hasattr(self, "ticketFile"):
            self.ticketFile = None
        if self.ticketFile:
            log.info("Using session ticket file `%s'." % self.ticketFile)
            const.TICKET_FILE = self.ticketFile

        # Used by the unpack mechanism
        self.totalLen = None
        self.payloadLen = None
        self.flags = None

        # Load replay dictionaries from file.
        if self.weAreServer:
            log.info("Loading replay dictionaries from file.")
            replay.UniformDH.loadFromDisk(const.UNIFORMDH_REPLAY_FILE)
            replay.SessionTicket.loadFromDisk(const.TICKET_REPLAY_FILE)


    def _deriveSecrets( self, masterKey ):
        """Derives session keys (AES keys, counter nonces and HMAC keys) from
        the given master key.  All key material is derived using
        HKDF-SHA256."""

        log.debug("Deriving session keys from master key 0x%s..." %
                  masterKey.encode('hex')[:10])

        # We need key material for two symmetric keys, nonces and HMACs.  All
        # of them are 32 bytes in size.
        hkdf = mycrypto.HKDF_SHA256(masterKey, "", 32 * 8)
        okm = hkdf.expand()

        # Set the symmetric AES keys.
        self.sendCrypter.setSessionKey(okm[0:32],  okm[32:64])
        self.recvCrypter.setSessionKey(okm[64:96], okm[96:128])

        # Set the HMAC keys.
        self.sendHMAC = okm[128:160]
        self.recvHMAC = okm[160:192]

        if self.weAreServer:
            self.sendHMAC, self.recvHMAC = util.swap(self.sendHMAC,
                                                     self.recvHMAC)
            self.sendCrypter, self.recvCrypter = util.swap(self.sendCrypter,
                                                           self.recvCrypter)


    def circuitDestroyed( self, circuit, reason, side ):
        """This method is called by obfsproxy when the TCP connection to the
        remote end was destroyed; either cleanly or in a non-clean fashion."""

        # This is only printed because the user might be interested in it.
        if reason and reason.check(error.ConnectionLost):
            log.info("The connection was lost in a non-clean fashion.")


    def handshake( self, circuit ):
        """This function is invoked after a circuit was established.  If a
        ticket is available, the client redeems it.  Otherwise, the client
        tries to start a UniformDH handshake."""

        # The server handles the handshake passively.
        if self.weAreServer:
            return

        if (self.uniformDHSecret is None) and (self.ticketFile is None):
            raise base.PluggableTransportError("Neither a UniformDH secret "
                    "nor a ticket is available.  %s needs at least one of "
                    "these for authentication." % const.TRANSPORT_NAME)

        # The preferred way to authenticate is a session ticket.
        storedTicket = ticket.findStoredTicket(circuit.downstream.peer_addr)
        if storedTicket is not None:

            (masterKey, rawTicket) = storedTicket
            log.debug("Redeeming session ticket 0x%s..." %
                      rawTicket.encode('hex')[:10])
            self._deriveSecrets(masterKey)

            # Subtract the length of the ticket to make the handshake on
            # average as long as a UniformDH handshake message.
            padding = mycrypto.weak_random(random.randint(0,
                                           const.MAX_PADDING_LENGTH -
                                           const.TICKET_LENGTH))

            marker = mycrypto.HMAC_SHA256_128(self.sendHMAC,
                                              self.sendHMAC + rawTicket)
            mac = mycrypto.HMAC_SHA256_128(self.sendHMAC, rawTicket + padding +
                                           marker + util.getEpoch())

            self._chopAndSend(circuit, rawTicket + padding + marker + mac,
                              protocolMsg=False)
            self.redeemedTicket = True

            # TODO - The client can't know at this point whether the server
            # accepted the ticket.
            log.debug("Switching to state ST_CONNECTED.")
            self.state = const.ST_CONNECTED
            self._flushSendBuffer(circuit)

        # Conduct an authenticated UniformDH handshake if there's no ticket.
        else:
            log.debug("No session ticket to redeem.  Running UniformDH.")
            self._chopAndSend(circuit, self.uniformdh.createHandshake(),
                              protocolMsg=False)


    def sendRemote( self, circuit, data, flags=const.FLAG_PAYLOAD ):
        """Encrypt, then chop the given data into pieces and send it to the
        remote end."""

        assert circuit

        if (data is None) or (len(data) == 0):
            return

        log.info("Processing %d bytes of outgoing data." % len(data))

        # Wrap the application's data in ScrambleSuit protocol messages.
        messages = message.createProtocolMessages(data, flags=flags)

        self._chopAndSend(circuit, messages)


    def _chopAndSend( self, circuit, messages, protocolMsg=True ):

        # Ask the packet morpher how much we should pad and get a chopper.
        chopper, paddingLen = self.pktMorpher.morph(sum([len(msg)
                                                    for msg in messages]))

        # If we are dealing with protocol messages, we pad, encrypt and MAC...
        if protocolMsg:
            if paddingLen > const.HDR_LENGTH:
                messages.append(message.ProtocolMessage("",
                                paddingLen=paddingLen - const.HDR_LENGTH))

            blurb = "".join([msg.encryptAndHMAC(self.sendCrypter,
                            self.sendHMAC) for msg in messages])

        # ...otherwise, we leave the data as it is.
        else:
            blurb = messages

        # Chop the encrypted blurb to fit the target probability distribution.
        self.choppedPieces += chopper(blurb)
        self.__flushPieces(circuit)


    def __flushPieces( self, circuit ):
        """Writes the cached and chopped data pieces to the wire using
        `circuit'. After every write, control is given back to the reactor so
        it has a chance to actually write the data. Shortly thereafter, this
        function is called again if data is left to write."""

        assert circuit

        if len(self.choppedPieces) == 0:
            return

        if len(self.choppedPieces[0]) > 0:
            log.debug("Writing %d bytes of data to downstream." %
                      len(self.choppedPieces[0]))
            circuit.downstream.write(self.choppedPieces[0])

        if len(self.choppedPieces) > 1:
            self.choppedPieces = self.choppedPieces[1:]
            reactor.callLater(self.iatMorpher.randomSample(),
                              self.__flushPieces, circuit)


    def extractMsgs( self, data, aes ):
        """Takes raw data from the wire, decrypts and authenticates the data
        and returns ScrambleSuit protocol messages."""

        assert aes and (data is not None)

        self.recvBuf += data
        msgs = []

        # Keep trying to unpack as long as there is at least a header.
        while len(self.recvBuf) >= const.HDR_LENGTH:

            # If necessary, extract the header fields.
            if self.totalLen == self.payloadLen == self.flags == None:
                self.totalLen = pack.ntohs(aes.decrypt(self.recvBuf[16:18]))
                self.payloadLen = pack.ntohs(aes.decrypt(self.recvBuf[18:20]))
                self.flags = ord(aes.decrypt(self.recvBuf[20]))

                if not message.isSane(self.totalLen,
                                      self.payloadLen, self.flags):
                    raise base.PluggableTransportError("Invalid header.")

            # Parts of the message are still on the wire; waiting.
            if (len(self.recvBuf) - const.HDR_LENGTH) < self.totalLen:
                break

            rcvdHMAC = self.recvBuf[0:const.HMAC_LENGTH]
            vrfyHMAC = mycrypto.HMAC_SHA256_128(self.recvHMAC,
                              self.recvBuf[const.HMAC_LENGTH:(self.totalLen +
                              const.HDR_LENGTH)])

            if rcvdHMAC != vrfyHMAC:
                raise base.PluggableTransportError("Invalid message HMAC.")

            # Decrypt the message and remove it from the input buffer.
            extracted = aes.decrypt(self.recvBuf[const.HDR_LENGTH:
                         (self.totalLen + const.HDR_LENGTH)])[:self.payloadLen]
            msgs.append(message.new(payload=extracted, flags=self.flags))
            self.recvBuf = self.recvBuf[const.HDR_LENGTH + self.totalLen:]

            # Protocol message processed; now reset length fields.
            self.totalLen = self.payloadLen = self.flags = None

        return msgs


    def processMessages( self, circuit, data ):
        """Deobfuscate, then decrypt the given data and send it to the local
        Tor client."""

        assert circuit

        if (data is None) or (len(data) == 0):
            return

        # Try to extract protocol messages from the encrypted blurb.
        msgs  = self.extractMsgs(data, self.recvCrypter)
        if (msgs is None) or (len(msgs) == 0):
            return

        for msg in msgs:
            # Forward data to the application.
            if msg.flags & const.FLAG_PAYLOAD:
                circuit.upstream.write(msg.payload)

            # Let replay protection kick in after ticket was confirmed.
            elif self.weAreServer and (msg.flags & const.FLAG_CONFIRM_TICKET):

                if self.ticketReplayCache is not None:
                    log.debug("Adding master key contained in ticket to the "
                              "replay table.")
                    replay.SessionTicket.addKey(self.ticketReplayCache)

                elif self.uniformdh.getRemotePublicKey() is not None:
                    log.debug("Adding the remote's UniformDH public key to "
                              "the replay table.")
                    replay.UniformDH.addKey(
                            self.uniformdh.getRemotePublicKey())

            # Store newly received ticket and send ACK to the server.
            elif self.weAreClient and msg.flags == const.FLAG_NEW_TICKET:
                assert len(msg) == (const.HDR_LENGTH + const.TICKET_LENGTH +
                                    const.MASTER_KEY_LENGTH)
                ticket.storeNewTicket(msg.payload[0:const.MASTER_KEY_LENGTH],
                                      msg.payload[const.MASTER_KEY_LENGTH:
                                                  const.MASTER_KEY_LENGTH +
                                                  const.TICKET_LENGTH],
                                      circuit.downstream.peer_addr)
                # Tell the server that we received the ticket.
                log.debug("Sending FLAG_CONFIRM_TICKET message to server.")
                self.sendRemote(circuit, "dummy",
                                flags=const.FLAG_CONFIRM_TICKET)

            else:
                log.warning("Invalid message flags: %d." % msg.flags)


    def _flushSendBuffer( self, circuit ):
        """Flushes the send buffer which could have been filled by the
        application while ScrambleSuit was still busy handling
        authentication."""

        assert circuit

        if len(self.sendBuf) == 0:
            return

        # Flush the buffered data, the application is so eager to send.
        log.debug("Flushing %d bytes of buffered application data." %
                  len(self.sendBuf))

        self.sendRemote(circuit, self.sendBuf)
        self.sendBuf = ""


    def _receiveTicket( self, data ):
        """Verify and extract ticket handshake message."""

        if len(data) < (const.TICKET_LENGTH + const.MARKER_LENGTH +
                        const.HMAC_LENGTH):
            return False

        potentialTicket = data.peek()

        # Now try to decrypt and parse the ticket.  We need the master key
        # inside to verify the HMAC in the next step.
        if not self.decryptedTicket:
            newTicket = ticket.decrypt(potentialTicket[:const.TICKET_LENGTH])
            if newTicket != None and newTicket.isValid():
                self._deriveSecrets(newTicket.masterKey)
                self.decryptedTicket = True
                self.ticketReplayCache = newTicket.masterKey
            else:
                return False

        # First, find the marker to efficiently locate the HMAC.
        marker = mycrypto.HMAC_SHA256_128(self.recvHMAC, self.recvHMAC +
                                         potentialTicket[:const.TICKET_LENGTH])

        index = util.locateMarker(marker, potentialTicket)
        if not index:
            return False

        # Now, verify if the HMAC is valid.
        existingHMAC = potentialTicket[index + const.MARKER_LENGTH:
                                       index + const.MARKER_LENGTH +
                                       const.HMAC_LENGTH]
        myHMAC = mycrypto.HMAC_SHA256_128(self.recvHMAC,
                                          potentialTicket[0:
                                          index + const.MARKER_LENGTH] +
                                          util.getEpoch())

        if not util.isValidHMAC(myHMAC, existingHMAC):
            return False

        data.drain(index + const.MARKER_LENGTH + const.HMAC_LENGTH)

        log.debug("Switching to state ST_CONNECTED.")
        self.state = const.ST_CONNECTED

        return True


    def receivedDownstream( self, data, circuit ):
        """Data coming from the remote end point and going to the local Tor."""

        if self.weAreServer and (self.state == const.ST_WAIT_FOR_AUTH):

            # First, try to interpret the incoming data as session ticket.
            if self._receiveTicket(data):
                log.debug("Ticket authentication succeeded.")
                self._flushSendBuffer(circuit)
                self.sendRemote(circuit, ticket.issueTicketAndKey(),
                                flags=const.FLAG_NEW_TICKET)

            # Second, interpret the data as a UniformDH handshake.
            elif self.uniformdh.receivePublicKey(data, self._deriveSecrets):
                # Now send the server's UniformDH public key to the client.
                handshakeMsg = self.uniformdh.createHandshake()
                newTicket = ticket.issueTicketAndKey()

                log.debug("Sending %d bytes of UniformDH handshake and "
                          "session ticket." % len(handshakeMsg))

                self._chopAndSend(circuit, handshakeMsg, protocolMsg=False)
                log.debug("UniformDH authentication succeeded.")
                self.sendRemote(circuit, newTicket, flags=const.FLAG_NEW_TICKET)

                log.debug("Switching to state ST_CONNECTED.")
                self.state = const.ST_CONNECTED
                self._flushSendBuffer(circuit)

            else:
                log.debug("Authentication unsuccessful so far.  "
                          "Waiting for more data.")
                return

        if self.weAreClient and (self.state == const.ST_WAIT_FOR_AUTH):

            if not self.uniformdh.receivePublicKey(data, self._deriveSecrets):
                log.debug("Unable to finish UniformDH handshake just yet.")
                return
            log.debug("Switching to state ST_CONNECTED.")
            self.state = const.ST_CONNECTED
            self._flushSendBuffer(circuit)

        if self.state == const.ST_CONNECTED:

            self.processMessages(circuit, data.read())


    def receivedUpstream( self, data, circuit ):
        """Data coming from the local Tor client and going to the remote
        bridge. If the data can't be sent immediately (in state ST_CONNECTED)
        it is buffered to be transmitted later."""

        if self.state == const.ST_CONNECTED:
            self.sendRemote(circuit, data.read())

        # Buffer data we are not ready to transmit yet.
        else:
            self.sendBuf += data.read()
            log.debug("%d bytes of outgoing data buffered." %
                      len(self.sendBuf))


    @classmethod
    def register_external_mode_cli( cls, subparser ):
        """Register a ScrambleSuit-specific command line argument for obfsproxy
        which can be used to pass the UniformDH shared secret to
        ScrambleSuit."""

        subparser.add_argument("--shared-secret", type=str,
                               help="Shared secret for UniformDH",
                               dest="uniformDHSecret")

        subparser.add_argument("--ticket-file", type=str, help="Path to a "
                               "session ticket (only for client)",
                               dest="ticketFile")

        super(ScrambleSuitTransport, cls).register_external_mode_cli(subparser)


    @classmethod
    def validate_external_mode_cli(cls, args):

        if args.uniformDHSecret:
            cls.uniformDHSecret = args.uniformDHSecret

        if args.ticketFile:
            cls.ticketFile = args.ticketFile

        if args.uniformDHSecret and (len(args.uniformDHSecret) !=
                                     const.SHARED_SECRET_LENGTH):
            raise base.PluggableTransportError("The UniformDH shared secret "
                    "must be %d bytes in length but %d bytes given." %
                    (const.SHARED_SECRET_LENGTH, len(args.uniformDHSecret)))

        super(ScrambleSuitTransport, cls).validate_external_mode_cli(args)


    def handle_socks_args( self, args ):
        """This method is called with arguments which are received over the
        SOCKS handshake.  That way, the UniformDH shared secret can reach
        ScrambleSuit over SOCKS."""

        log.debug("Received the following arguments over SOCKS: %s." % args)

        # A shared secret might already be set if obfsproxy is in
        # external mode.
        if self.uniformDHSecret:
            log.info("A UniformDH shared secret was already specified over"
                     "the command line.  Using the SOCKS secret.")

        if len(args) != 1:
            raise base.SOCKSArgsError("Too many SOCKS arguments "
                                      "(expected 1 but got %d)." % len(args))

        if not args[0].startswith("shared-secret="):
            raise base.SOCKSArgsError("The SOCKS argument should start with"
                                      "`shared-secret='.")

        self.uniformDHSecret = args[0][14:]

        if len(args.uniformDHSecret) != const.SHARED_SECRET_LENGTH:
            raise base.PluggableTransportError("The UniformDH shared secret "
                    "must be %d bytes in length but %d bytes given." %
                    (const.SHARED_SECRET_LENGTH, len(args.uniformDHSecret)))


class ScrambleSuitClient( ScrambleSuitTransport ):

    def __init__( self ):
        self.weAreClient = True
        self.weAreServer = False
        ScrambleSuitTransport.__init__(self)


class ScrambleSuitServer( ScrambleSuitTransport ):

    def __init__( self ):
        self.weAreServer = True
        self.weAreClient = False
        ScrambleSuitTransport.__init__(self)
