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

import random

import probdist
import mycrypto
import message
import const
import util
import packetmorpher
import ticket
import replay
import uniformdh
import state


log = logging.get_obfslogger()


class ScrambleSuitTransport( base.BaseTransport ):

    """
    Implement the ScrambleSuit protocol.

    The class implements methods which implement the ScrambleSuit protocol.  A
    large part of the protocol's functionality is outsources to different
    modules.
    """

    def __init__( self ):
        """
        Initialise a ScrambleSuitTransport object.
        """

        log.error("\n+++ Note that ScrambleSuit is still under "
                  "development and is NOT safe for practical use. +++\n")

        log.debug("Initialising %s." % const.TRANSPORT_NAME)

        # Load the server's persistent state from file.
        if self.weAreServer:
            self.srvState = state.load()

        # Initialise the protocol's state machine.
        log.debug("Switching to state ST_WAIT_FOR_AUTH.")
        self.protoState = const.ST_WAIT_FOR_AUTH

        # Buffers for incoming and outgoing data.
        self.sendBuf = self.recvBuf = ""

        # Caches the outgoing data before written to the wire.
        self.choppingBuf = ""

        # AES instances for incoming and outgoing data.
        self.sendCrypter = mycrypto.PayloadCrypter()
        self.recvCrypter = mycrypto.PayloadCrypter()

        # Packet morpher to modify the protocol's packet length distribution.
        self.pktMorpher = packetmorpher.PacketMorpher(self.srvState.pktDist
                          if self.weAreServer else None)

        # Inter arrival time morpher to obfuscate inter arrival times.
        self.iatMorpher = self.srvState.iatDist if self.weAreServer else \
                          probdist.new(lambda: random.random() %
                                       const.MAX_PACKET_DELAY)

        # `True' if the ticket is already decrypted but not yet authenticated.
        self.decryptedTicket = None

        # Cache the master key so it can later be added to the replay table.
        self.ticketReplayCache = None

        # Shared secret k_B which is only used for UniformDH.
        if not hasattr(self, "uniformDHSecret"):
            self.uniformDHSecret = None
        else:
            log.debug("UniformDH shared secret is given.")
            self.uniformdh = uniformdh.new(self.uniformDHSecret,
                                           self.weAreServer)

        # Check for a session ticket in a custom location.
        if not hasattr(self, "ticketFile"):
            self.ticketFile = const.CLIENT_TICKET_FILE
        else:
            log.debug("Custom session ticket file `%s' was given." %
                      self.ticketFile)

        # Used by the unpack mechanism
        self.totalLen = self.payloadLen = self.flags = None

    def _deriveSecrets( self, masterKey ):
        """
        Derive session keys from the given master key.

        The argument `masterKey' is used to derive two session keys and nonces
        for AES-CTR and two HMAC keys.  The derivation is done using
        HKDF-SHA256.
        """

        assert len(masterKey) == const.MASTER_KEY_LENGTH

        log.debug("Deriving session keys from master key.")

        # We need key material for two symmetric keys, nonces and HMACs.  All
        # of these six are 32 bytes in size.
        hkdf = mycrypto.HKDF_SHA256(masterKey, "", 32 * 8)
        okm = hkdf.expand()

        self.sendCrypter.setSessionKey(okm[0:32],  okm[32:64])
        self.recvCrypter.setSessionKey(okm[64:96], okm[96:128])

        self.sendHMAC = okm[128:160]
        self.recvHMAC = okm[160:192]

        if self.weAreServer:
            self.sendHMAC, self.recvHMAC = util.swap(self.sendHMAC,
                                                     self.recvHMAC)
            self.sendCrypter, self.recvCrypter = util.swap(self.sendCrypter,
                                                           self.recvCrypter)

    def circuitDestroyed( self, circuit, reason, side ):
        """
        Log a warning if the connection was closed in a non-clean fashion.
        """

        # This is only printed because the user might be interested in it.
        if reason and reason.check(error.ConnectionLost):
            log.info("The connection was lost in a non-clean fashion.")

    def handshake( self, circuit ):
        """
        Initiate a ScrambleSuit handshake.

        This method is only relevant for clients.  If a session ticket is
        available it is redeemed.  Otherwise, a UniformDH handshake is
        initiated.
        """

        # The server handles the handshake passively.
        if self.weAreServer:
            return

        # The preferred way to authenticate is a session ticket.
        srvAddr = circuit.downstream.transport.getPeer()
        storedTicket = ticket.findStoredTicket(srvAddr,
                                               fileName=self.ticketFile)
        if storedTicket is not None:
            log.debug("Redeeming stored session ticket.")
            (masterKey, rawTicket) = storedTicket
            self._deriveSecrets(masterKey)

            circuit.downstream.write(ticket.createTicketMessage(rawTicket,
                                                                self.sendHMAC))

            # We switch to ST_CONNECTED opportunistically since we don't know
            # yet whether the server accepted the ticket.
            log.debug("Switching to state ST_CONNECTED.")
            self.protoState = const.ST_CONNECTED
            self._flushSendBuffer(circuit)

        # Conduct an authenticated UniformDH handshake if there's no ticket.
        elif self.uniformDHSecret is not None:
            log.debug("No session ticket to redeem.  Running UniformDH.")
            circuit.downstream.write(self.uniformdh.createHandshake())

        else:
            log.error("Neither a UniformDH secret nor a ticket is available."
                      "  %s needs at least one of these for authentication." %
                      const.TRANSPORT_NAME)
            raise base.PluggableTransportError("Unable to authenticate.")

    def sendRemote( self, circuit, data, flags=const.FLAG_PAYLOAD ):
        """
        Send data to the remote end after a connection was established.

        The given `data' is first encapsulated in protocol messages.  Then, the
        protocol message(s) are sent over the wire using the given `circuit'.
        The argument `flags' specifies the protocol message flags with the
        default flags signalling payload.
        """

        log.debug("Processing %d bytes of outgoing data." % len(data))

        # Wrap the application's data in ScrambleSuit protocol messages.
        messages = message.createProtocolMessages(data, flags=flags)

        # Let the packet morpher tell us how much we should pad.
        paddingLen = self.pktMorpher.calcPadding(sum([len(msg) for
                                                 msg in messages]))

        # If padding > header length, a single message will do...
        if paddingLen > const.HDR_LENGTH:
            messages.append(message.new("", paddingLen=paddingLen -
                                                       const.HDR_LENGTH))

        # ...otherwise, we use two padding-only messages.
        else:
            messages.append(message.new("", paddingLen=const.MPU -
                                                       const.HDR_LENGTH))
            messages.append(message.new("", paddingLen=paddingLen))

        blurb = "".join([msg.encryptAndHMAC(self.sendCrypter,
                        self.sendHMAC) for msg in messages])

        # Flush data chunk for chunk to obfuscate inter arrival times.
        if len(self.choppingBuf) == 0:
            self.choppingBuf += blurb
            reactor.callLater(self.iatMorpher.randomSample(),
                              self._flushPieces, circuit)
        else:
            # _flushPieces() is still busy processing the chopping buffer.
            self.choppingBuf += blurb

    def _flushPieces( self, circuit ):
        """
        Write the application data in chunks to the wire.

        The cached data is written in chunks to `circuit'.  After every write
        call, control is given back to the Twisted reactor so it has a chance
        to flush the data.  Shortly thereafter, this function is called again
        to write the next chunk of data.  The delays in between subsequent
        write calls are controlled by the inter arrival time obfuscator.
        """

        # Drain and send an MTU-sized chunk from the chopping buffer.
        if len(self.choppingBuf) > const.MTU:
            circuit.downstream.write(self.choppingBuf[0:const.MTU])
            self.choppingBuf = self.choppingBuf[const.MTU:]

        # Drain and send whatever is left in the output buffer.
        else:
            circuit.downstream.write(self.choppingBuf)
            self.choppingBuf = ""
            return

        reactor.callLater(self.iatMorpher.randomSample(),
                          self._flushPieces, circuit)

    def extractMessages( self, data, aes ):
        """
        Unpacks (i.e., decrypts and authenticates) protocol messages.

        The raw `data' coming directly from the wire is decrypted using `aes'
        and authenticated.  The payload (be it a session ticket or actual
        payload) is then returned as unencrypted protocol messages.  In case of
        invalid headers or HMACs, an exception is raised.
        """

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
        """
        Acts on extracted protocol messages based on header flags.

        After the incoming `data' is decrypted and authenticated, this method
        processes the received data based on the header flags.  Payload is
        written to the local application using `circuit', new tickets are
        stored or keys are added to the replay table.
        """

        assert circuit

        if (data is None) or (len(data) == 0):
            return

        # Try to extract protocol messages from the encrypted blurb.
        msgs  = self.extractMessages(data, self.recvCrypter)
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
                    self.srvState.registerKey(self.ticketReplayCache)

                elif self.uniformdh.getRemotePublicKey() is not None:
                    log.debug("Adding the remote's UniformDH public key to "
                              "the replay table.")
                    self.srvState.registerKey(
                            self.uniformdh.getRemotePublicKey())

            # Store newly received ticket and send ACK to the server.
            elif self.weAreClient and msg.flags == const.FLAG_NEW_TICKET:
                assert len(msg) == (const.HDR_LENGTH + const.TICKET_LENGTH +
                                    const.MASTER_KEY_LENGTH)
                peer = circuit.downstream.transport.getPeer()
                ticket.storeNewTicket(msg.payload[0:const.MASTER_KEY_LENGTH],
                                      msg.payload[const.MASTER_KEY_LENGTH:
                                                  const.MASTER_KEY_LENGTH +
                                                  const.TICKET_LENGTH], peer)
                # Tell the server that we received the ticket.
                log.debug("Sending FLAG_CONFIRM_TICKET message to server.")
                self.sendRemote(circuit, "", flags=const.FLAG_CONFIRM_TICKET)

            # Use the PRNG seed to generate the same probability distributions
            # as the server.  That's where the polymorphism comes from.
            elif self.weAreClient and msg.flags == const.FLAG_PRNG_SEED:
                assert len(msg.payload) == const.PRNG_SEED_LENGTH
                log.debug("Obtained PRNG seed.")
                prng = random.Random(msg.payload)
                pktDist = probdist.new(lambda: prng.randint(const.HDR_LENGTH,
                                                            const.MTU),
                                       seed=msg.payload)
                self.pktMorpher = packetmorpher.new(pktDist)
                self.iatMorpher = probdist.new(lambda: prng.random() %
                                               const.MAX_PACKET_DELAY,
                                               seed=msg.payload)

            else:
                log.warning("Invalid message flags: %d." % msg.flags)

    def _flushSendBuffer( self, circuit ):
        """
        Flush the application's queued data.

        The application could have sent data while we were busy authenticating
        the remote machine.  Using `circuit', this method flushes the data
        which could have been queued in the meanwhile in `self.sendBuf'.
        """

        assert circuit

        if len(self.sendBuf) == 0:
            return

        # Flush the buffered data, the application is so eager to send.
        log.debug("Flushing %d bytes of buffered application data." %
                  len(self.sendBuf))

        self.sendRemote(circuit, self.sendBuf)
        self.sendBuf = ""

    def _receiveTicket( self, data ):
        """
        Extract and verify a potential session ticket.

        The given `data' is treated as a session ticket.  The ticket is being
        decrypted and authenticated (yes, in that order).  If all these steps
        succeed, `True' is returned.  Otherwise, `False' is returned.
        """

        if len(data) < (const.TICKET_LENGTH + const.MARKER_LENGTH +
                        const.HMAC_LENGTH):
            return False

        potentialTicket = data.peek()

        # Now try to decrypt and parse the ticket.  We need the master key
        # inside to verify the HMAC in the next step.
        if not self.decryptedTicket:
            newTicket = ticket.decrypt(potentialTicket[:const.TICKET_LENGTH],
                                       self.srvState)
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

        if not util.isValidHMAC(myHMAC, existingHMAC, self.recvHMAC):
            return False

        data.drain(index + const.MARKER_LENGTH + const.HMAC_LENGTH)

        log.debug("Switching to state ST_CONNECTED.")
        self.protoState = const.ST_CONNECTED

        return True

    def receivedUpstream( self, data, circuit ):
        """
        Sends data to the remote machine or queues it to be sent later.

        Depending on the current protocol state, the given `data' is either
        directly sent to the remote machine using `circuit' or queued.  The
        buffer is then flushed once, a connection is established.
        """

        if self.protoState == const.ST_CONNECTED:
            self.sendRemote(circuit, data.read())

        # Buffer data we are not ready to transmit yet.
        else:
            self.sendBuf += data.read()
            log.debug("%d bytes of outgoing data buffered." %
                      len(self.sendBuf))

    def receivedDownstream( self, data, circuit ):
        """
        Receives and processes data coming from the remote machine.

        The incoming `data' is dispatched depending on the current protocol
        state and whether we are the client or the server.  The data is either
        payload or authentication data.
        """

        if self.weAreServer and (self.protoState == const.ST_WAIT_FOR_AUTH):

            # First, try to interpret the incoming data as session ticket.
            if self._receiveTicket(data):
                log.debug("Ticket authentication succeeded.")
                self._flushSendBuffer(circuit)
                self.sendRemote(circuit,
                                ticket.issueTicketAndKey(self.srvState),
                                flags=const.FLAG_NEW_TICKET)
                self.sendRemote(circuit, self.srvState.prngSeed,
                                flags=const.FLAG_PRNG_SEED)

            # Second, interpret the data as a UniformDH handshake.
            elif self.uniformdh.receivePublicKey(data, self._deriveSecrets):
                # Now send the server's UniformDH public key to the client.
                handshakeMsg = self.uniformdh.createHandshake()
                newTicket = ticket.issueTicketAndKey(self.srvState)

                log.debug("Sending %d bytes of UniformDH handshake and "
                          "session ticket." % len(handshakeMsg))

                circuit.downstream.write(handshakeMsg)

                log.debug("UniformDH authentication succeeded.")
                self.sendRemote(circuit, newTicket,
                                flags=const.FLAG_NEW_TICKET)
                self.sendRemote(circuit, self.srvState.prngSeed,
                                flags=const.FLAG_PRNG_SEED)

                log.debug("Switching to state ST_CONNECTED.")
                self.protoState = const.ST_CONNECTED
                self._flushSendBuffer(circuit)

            else:
                log.debug("Authentication unsuccessful so far.  "
                          "Waiting for more data.")
                return

        if self.weAreClient and (self.protoState == const.ST_WAIT_FOR_AUTH):

            if not self.uniformdh.receivePublicKey(data, self._deriveSecrets):
                log.debug("Unable to finish UniformDH handshake just yet.")
                return
            log.debug("Switching to state ST_CONNECTED.")
            self.protoState = const.ST_CONNECTED
            self._flushSendBuffer(circuit)

        if self.protoState == const.ST_CONNECTED:

            self.processMessages(circuit, data.read())

    @classmethod
    def register_external_mode_cli( cls, subparser ):
        """
        Register a CLI arguments to pass a secret or ticket to ScrambleSuit.

        Two options are made available over the command line interface: one to
        specify a ticket file and one to specify a UniformDH shared secret.
        """

        subparser.add_argument("--shared-secret",
                               type=str,
                               help="Shared secret for UniformDH",
                               dest="uniformDHSecret")

        subparser.add_argument("--ticket-file",
                               type=str,
                               help="Path to a session ticket (client only)",
                               dest="ticketFile")

        super(ScrambleSuitTransport, cls).register_external_mode_cli(subparser)

    @classmethod
    def validate_external_mode_cli( cls, args ):
        """
        Assign the given command line arguments to local variables.
        """

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
        """
        Receive arguments passed over a SOCKS connection.

        The SOCKS authentication mechanism is (ab)used to pass arguments to
        pluggable transports.  This method receives these arguments and parses
        them.  As argument, we only expect a UniformDH shared secret.
        """

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

    """
    Extend the ScrambleSuit class.
    """

    def __init__( self ):
        """
        Initialise a ScrambleSuitClient object.
        """

        self.weAreClient = True
        self.weAreServer = False
        ScrambleSuitTransport.__init__(self)


class ScrambleSuitServer( ScrambleSuitTransport ):

    """
    Extend the ScrambleSuit class.
    """

    def __init__( self ):
        """
        Initialise a ScrambleSuitServer object.
        """

        self.weAreServer = True
        self.weAreClient = False
        ScrambleSuitTransport.__init__(self)
