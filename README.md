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
by conducting a modified UniformDH handshake or by redeeming a session ticket.

For a more detailed overview of ScrambleSuit, please have a look at the project
page available at <http://veri.nymity.ch/scramblesuit/>.  The research paper is
available at <http://veri.nymity.ch/pdf/wpes2013.pdf>.  Finally, the directory
"doc/" in this repository contains ScrambleSuit's protocol specification.

Installation and Testing
========================

The following instructions were tested on Debian wheezy but they should work
just fine on other GNU/Linux distributions as well.

1. On a Debian wheezy system, the following packages are needed:  
   `git`, `python-dev`, `python-gmpy`, `python-yaml`, `python-setuptools`,
   `automake`, `libevent-dev`, `libssl-dev`, `asciidoc`

2. Clone and compile the current Tor-git (or use a version of your choice as
   long as it is >= v0.2.5.0-alpha-dev):  
   `git clone https://git.torproject.org/tor.git`

3. Clone the current version of pyptlib (or use a version of your choice as
   long as it is >= 0.0.5):  
   `git clone https://git.torproject.org/pluggable-transports/pyptlib.git`

4. Clone a modified version of obfsproxy which contains the scramblesuit
   branch:  
   `git clone -b scramblesuit_integration https://git.torproject.org/user/phw/obfsproxy.git`

The directory "test/" in this repository contains two configuration files for
`tor` which provide a local (i.e., using the loopback interface) ScrambleSuit
setup.  Furthermore, the script `generate_secret.py` can be used to generate
shared secrets for Tor's configuration file.

Alternatives
============

Check out [obfs4](https://gitweb.torproject.org/pluggable-transports/obfs4.git)
which is an enhancement of ScrambleSuit.

Feedback
========

Contact: Philipp Winter <phw@torproject.org>  
OpenPGP fingerprint: `B369 E7A2 18FE CEAD EB96  8C73 CF70 89E3 D7FD C0D0`
