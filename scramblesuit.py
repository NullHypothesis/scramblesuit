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
import base64

import probdist
import mycrypto
import message
import const
import util
import packetmorpher
import ticket
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

    def __init__( self, transportConfig ):
        """
        Initialise a ScrambleSuitTransport object.
        """

        log.error("\n\n################################################\n"
                  "Do NOT rely on ScrambleSuit for strong security!\n"
                  "################################################\n")

        log.debug("Initialising %s." % const.TRANSPORT_NAME)

        util.setStateLocation(transportConfig.getStateLocation())

        # Load the server's persistent state from file.
        if self.weAreServer:
            self.srvState = state.load()

        # Initialise the protocol's state machine.
        log.debug("Switching to state ST_WAIT_FOR_AUTH.")
        self.protoState = const.ST_WAIT_FOR_AUTH

        # Buffers for incoming and outgoing data.
        self.sendBuf = self.recvBuf = ""

        # Buffer for inter-arrival time obfuscation.
        self.choppingBuf = ""

        # AES instances to decrypt incoming and encrypt outgoing data.
        self.sendCrypter = mycrypto.PayloadCrypter()
        self.recvCrypter = mycrypto.PayloadCrypter()

        # Packet morpher to modify the protocol's packet length distribution.
        self.pktMorpher = packetmorpher.new(self.srvState.pktDist
                                            if self.weAreServer else None)

        # Inter-arrival time morpher to obfuscate inter arrival times.
        self.iatMorpher = self.srvState.iatDist if self.weAreServer else \
                          probdist.new(lambda: random.random() %
                                       const.MAX_PACKET_DELAY)

        if self.weAreServer:
            # `True' if the ticket is already decrypted but not yet
            # authenticated.
            self.decryptedTicket = False

            if not hasattr(self, 'uniformDHSecret'):

                # As the server, we get the shared secret from the constructor.
                cfg  = transportConfig.getServerTransportOptions()
                self.uniformDHSecret = base64.b32decode(cfg["password"])
                self.uniformDHSecret = self.uniformDHSecret.strip()

        else:
            # As the client, we get the shared secret from obfsproxy calling
            # `handle_socks_args()'.
            if not hasattr(self, 'uniformDHSecret'):
                self.uniformDHSecret = None

        self.uniformdh = uniformdh.new(self.uniformDHSecret, self.weAreServer)

        # Variables used to unpack protocol messages.
        self.totalLen = self.payloadLen = self.flags = None

    def deriveSecrets( self, masterKey ):
        """
        Derive various session keys from the given `masterKey'.

        The argument `masterKey' is used to derive two session keys and nonces
        for AES-CTR and two HMAC keys.  The derivation is done using
        HKDF-SHA256.
        """

        assert len(masterKey) == const.MASTER_KEY_LENGTH

        log.debug("Deriving session keys from %d-byte master key." %
                  len(masterKey))

        # We need key material for two symmetric AES-CTR keys, nonces and
        # HMACs.  In total, this equals 144 bytes of key material.
        hkdf = mycrypto.HKDF_SHA256(masterKey, "", (32 * 4) + (8 * 2))
        okm = hkdf.expand()
        assert len(okm) >= ((32 * 4) + (8 * 2))

        # Set AES-CTR keys and nonces for our two AES instances.
        self.sendCrypter.setSessionKey(okm[0:32],  okm[32:40])
        self.recvCrypter.setSessionKey(okm[40:72], okm[72:80])

        # Set the keys for the two HMACs protecting our data integrity.
        self.sendHMAC = okm[80:112]
        self.recvHMAC = okm[112:144]

        if self.weAreServer:
            self.sendHMAC, self.recvHMAC = util.swap(self.sendHMAC,
                                                     self.recvHMAC)
            self.sendCrypter, self.recvCrypter = util.swap(self.sendCrypter,
                                                           self.recvCrypter)

    def handshake( self, circuit ):
        """
        Initiate a ScrambleSuit handshake over `circuit'.

        This method is only relevant for clients since servers never initiate
        handshakes.  If a session ticket is available, it is redeemed.
        Otherwise, a UniformDH handshake is conducted.
        """

        # The server handles the handshake passively.
        if self.weAreServer:
            return

        # The preferred authentication mechanism is a session ticket.
        bridge = circuit.downstream.transport.getPeer()
        storedTicket = ticket.findStoredTicket(bridge)

        if storedTicket is not None:
            log.debug("Redeeming stored session ticket.")
            (masterKey, rawTicket) = storedTicket
            self.deriveSecrets(masterKey)
            circuit.downstream.write(ticket.createTicketMessage(rawTicket,
                                                                self.sendHMAC))

            # We switch to ST_CONNECTED opportunistically since we don't know
            # yet whether the server accepted the ticket.
            log.debug("Switching to state ST_CONNECTED.")
            self.protoState = const.ST_CONNECTED

            self.flushSendBuffer(circuit)

        # Conduct an authenticated UniformDH handshake if there's no ticket.
        else:
            log.debug("No session ticket to redeem.  Running UniformDH.")
            circuit.downstream.write(self.uniformdh.createHandshake())

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
                              self.flushPieces, circuit)
        else:
            # flushPieces() is still busy processing the chopping buffer.
            self.choppingBuf += blurb

    def flushPieces( self, circuit ):
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
                          self.flushPieces, circuit)

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

            rcvdHMAC = self.recvBuf[0:const.HMAC_SHA256_128_LENGTH]
            vrfyHMAC = mycrypto.HMAC_SHA256_128(self.recvHMAC,
                              self.recvBuf[const.HMAC_SHA256_128_LENGTH:
                              (self.totalLen + const.HDR_LENGTH)])

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

            # Store newly received ticket and send ACK to the server.
            elif self.weAreClient and msg.flags == const.FLAG_NEW_TICKET:
                assert len(msg) == (const.HDR_LENGTH + const.TICKET_LENGTH +
                                    const.MASTER_KEY_LENGTH)
                peer = circuit.downstream.transport.getPeer()
                ticket.storeNewTicket(msg.payload[0:const.MASTER_KEY_LENGTH],
                                      msg.payload[const.MASTER_KEY_LENGTH:
                                                  const.MASTER_KEY_LENGTH +
                                                  const.TICKET_LENGTH], peer)

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

    def flushSendBuffer( self, circuit ):
        """
        Flush the application's queued data.

        The application could have sent data while we were busy authenticating
        the remote machine.  Using `circuit', this method flushes the data
        which could have been queued in the meanwhile in `self.sendBuf'.
        """

        assert circuit

        if len(self.sendBuf) == 0:
            log.debug("Send buffer is empty; nothing to flush.")
            return

        # Flush the buffered data, the application is so eager to send.
        log.debug("Flushing %d bytes of buffered application data." %
                  len(self.sendBuf))

        self.sendRemote(circuit, self.sendBuf)
        self.sendBuf = ""

    def receiveTicket( self, data ):
        """
        Extract and verify a potential session ticket.

        The given `data' is treated as a session ticket.  The ticket is being
        decrypted and authenticated (yes, in that order).  If all these steps
        succeed, `True' is returned.  Otherwise, `False' is returned.
        """

        if len(data) < (const.TICKET_LENGTH + const.MARK_LENGTH +
                        const.HMAC_SHA256_128_LENGTH):
            return False

        potentialTicket = data.peek()

        # Now try to decrypt and parse the ticket.  We need the master key
        # inside to verify the HMAC in the next step.
        if not self.decryptedTicket:
            newTicket = ticket.decrypt(potentialTicket[:const.TICKET_LENGTH],
                                       self.srvState)
            if newTicket != None and newTicket.isValid():
                self.deriveSecrets(newTicket.masterKey)
                self.decryptedTicket = True
            else:
                return False

        # First, find the mark to efficiently locate the HMAC.
        mark = mycrypto.HMAC_SHA256_128(self.recvHMAC,
                                        potentialTicket[:const.TICKET_LENGTH])

        index = util.locateMark(mark, potentialTicket)
        if not index:
            return False

        # Now, verify if the HMAC is valid.
        existingHMAC = potentialTicket[index + const.MARK_LENGTH:
                                       index + const.MARK_LENGTH +
                                       const.HMAC_SHA256_128_LENGTH]
        myHMAC = mycrypto.HMAC_SHA256_128(self.recvHMAC,
                                          potentialTicket[0:
                                          index + const.MARK_LENGTH] +
                                          util.getEpoch())

        if not util.isValidHMAC(myHMAC, existingHMAC, self.recvHMAC):
            log.warning("The HMAC is invalid: `%s' vs. `%s'." %
                        (myHMAC.encode('hex'), existingHMAC.encode('hex')))
            return False

        # Do nothing if the ticket is replayed.  Immediately closing the
        # connection would be suspicious.
        if self.srvState.isReplayed(existingHMAC):
            log.warning("The HMAC was already present in the replay table.")
            return False

        data.drain(index + const.MARK_LENGTH + const.HMAC_SHA256_128_LENGTH)

        log.debug("Adding the HMAC authenticating the ticket message to the " \
                  "replay table: %s." % existingHMAC.encode('hex'))
        self.srvState.registerKey(existingHMAC)

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
            log.debug("Buffered %d bytes of outgoing data." %
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
            if self.receiveTicket(data):
                log.debug("Ticket authentication succeeded.")
                self.sendRemote(circuit,
                                ticket.issueTicketAndKey(self.srvState),
                                flags=const.FLAG_NEW_TICKET)
                self.sendRemote(circuit, self.srvState.prngSeed,
                                flags=const.FLAG_PRNG_SEED)
                self.flushSendBuffer(circuit)

            # Second, interpret the data as a UniformDH handshake.
            elif self.uniformdh.receivePublicKey(data, self.deriveSecrets,
                    self.srvState):
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
                self.flushSendBuffer(circuit)

            else:
                log.debug("Authentication unsuccessful so far.  "
                          "Waiting for more data.")
                return

        if self.weAreClient and (self.protoState == const.ST_WAIT_FOR_AUTH):

            if not self.uniformdh.receivePublicKey(data, self.deriveSecrets):
                log.debug("Unable to finish UniformDH handshake just yet.")
                return
            log.debug("Switching to state ST_CONNECTED.")
            self.protoState = const.ST_CONNECTED
            self.flushSendBuffer(circuit)

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

        super(ScrambleSuitTransport, cls).register_external_mode_cli(subparser)

    @classmethod
    def validate_external_mode_cli( cls, args ):
        """
        Assign the given command line arguments to local variables.
        """

        if args.uniformDHSecret:
            cls.uniformDHSecret = base64.b32decode(args.uniformDHSecret)

        rawLength = len(base64.b32decode(args.uniformDHSecret))

        if args.uniformDHSecret and rawLength != const.SHARED_SECRET_LENGTH:
            raise base.PluggableTransportError("The UniformDH shared secret "
                    "must be %d bytes in length but %d bytes are given." %
                    (const.SHARED_SECRET_LENGTH, rawLength))

        super(ScrambleSuitTransport, cls).validate_external_mode_cli(args)

    def handle_socks_args( self, args ):
        """
        Receive arguments `args' passed over a SOCKS connection.

        The SOCKS authentication mechanism is (ab)used to pass arguments to
        pluggable transports.  This method receives these arguments and parses
        them.  As argument, we only expect a UniformDH shared secret.
        """

        log.debug("Received the following arguments over SOCKS: %s." % args)

        if len(args) != 1:
            raise base.SOCKSArgsError("Too many SOCKS arguments "
                                      "(expected 1 but got %d)." % len(args))

        # The ScrambleSuit specification defines that the shared secret is
        # called "password".
        if not args[0].startswith("password="):
            raise base.SOCKSArgsError("The SOCKS argument must start with "
                                      "`password='.")

        # A shared secret might already be set if obfsproxy is in external
        # mode.
        if self.uniformDHSecret:
            log.warning("A UniformDH shared secret was already specified over "
                        "the command line.  Using the SOCKS secret instead.")

        self.uniformDHSecret = base64.b32decode(args[0].split('=')[1].strip())

        rawLength = len(self.uniformDHSecret)
        if rawLength != const.SHARED_SECRET_LENGTH:
            raise base.PluggableTransportError("The UniformDH shared secret "
                    "must be %d bytes in length but %d bytes are given." %
                    (const.SHARED_SECRET_LENGTH, rawLength))

        self.uniformdh = uniformdh.new(self.uniformDHSecret, self.weAreServer)


class ScrambleSuitClient( ScrambleSuitTransport ):

    """
    Extend the ScrambleSuit class.
    """

    def __init__( self, transportConfig ):
        """
        Initialise a ScrambleSuitClient object.
        """

        self.weAreClient = True
        self.weAreServer = False
        ScrambleSuitTransport.__init__(self, transportConfig)


class ScrambleSuitServer( ScrambleSuitTransport ):

    """
    Extend the ScrambleSuit class.
    """

    def __init__( self, transportConfig ):
        """
        Initialise a ScrambleSuitServer object.
        """

        self.weAreServer = True
        self.weAreClient = False
        ScrambleSuitTransport.__init__(self, transportConfig)
