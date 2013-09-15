**WARNING: ScrambleSuit is NOT YET SAFE for practical use!**
------------------------------------------------------------

Overview
========

ScrambleSuit is a pluggable transport protocol for `obfsproxy`.  It is written
in pure Python and solves two problems:

* Protection against active probing attacks by requiring a *shared secret*
  between the client and the server.  This secret is communicated *out-of-band*
  via Tor's BridgeDB.
* Rudimentary defence against traffic analysis attacks by *altering flow
  features*.  In particular, ScrambleSuit alters its inter-arrival times and
  packet length distribution.

Besides, ScrambleSuit's payload is computationally indistinguishable from
randomness.  Clients can authenticate themselves towards a ScrambleSuit bridge
by conducting a modified UniformDH handshake or by redeeming a special session
ticket.

For a more detailed overview of ScrambleSuit, please have a look at the project
page available at <http://veri.nymity.ch/scramblesuit/>.  The research paper is
available at <http://veri.nymity.ch/pdf/wpes2013.pdf>.  Finally, the directory
"doc/" in this repository contains the protocol specification of ScrambleSuit.

Installation and Testing
========================

The following software is needed in order to test ScrambleSuit:

* `tor` in version v0.2.5.0-alpha-dev or newer.
* `obfsproxy` with the code branch bug8979_draft checked out.
* `pyptlib` with the code branch bug8979_take2 checked out.

First, you have to copy ScrambleSuit's Python files into `obfsproxy`'s
"obfsproxy/transports/" directory.  Finally, apply the following patch to
`obfsproxy`'s "transports.py" file.  It will make `obfsproxy` aware that
ScrambleSuit exists:

    --- a/obfsproxy/transports/transports.py
    +++ b/obfsproxy/transports/transports.py
    @@ -3,9 +3,11 @@ import obfsproxy.transports.dummy as dummy
     import obfsproxy.transports.b64 as b64
     import obfsproxy.transports.obfs2 as obfs2
     import obfsproxy.transports.obfs3 as obfs3
    +import obfsproxy.transports.scramblesuit as scramblesuit

     transports = { 'dummy' : {'base': dummy.DummyTransport, 'client' : dummy.DummyClient, 'server' : dummy.DummyServer },
                    'b64'   : {'base': b64.B64Transport, 'client' : b64.B64Client, 'server' : b64.B64Server },
    +               'scramblesuit' : {'base': scramblesuit.ScrambleSuitTransport, 'client' : scramblesuit.ScrambleSuitClient, 'server' : scramblesuit.ScrambleSuitServer },
                    'obfs2' : {'base': obfs2.Obfs2Transport, 'client' : obfs2.Obfs2Client, 'server' : obfs2.Obfs2Server },
                    'obfs3' : {'base': obfs3.Obfs3Transport, 'client' : obfs3.Obfs3Client, 'server' : obfs3.Obfs3Server } }

The directory "test/" in this repository contains two configuration files for
`tor` which provide a simple ScrambleSuit setup.  They can be run by invoking
`tor -f torrc.server` on the server and `tor -f torrc.client` on the client
(You can use the `PYTHONPATH` environment variable to point towards your custom
checkout of `obfsproxy` and `pyptlib`).  This will start a ScrambleSuit bridge
waiting for connections on the loopback interface 127.0.0.1:65535.  The client
will then try to connect to the bridge.

Feedback
========

Contact: Philipp Winter <phw@torproject.org>  
OpenPGP fingerprint: B369 E7A2 18FE CEAD EB96  8C73 CF70 89E3 D7FD C0D0
