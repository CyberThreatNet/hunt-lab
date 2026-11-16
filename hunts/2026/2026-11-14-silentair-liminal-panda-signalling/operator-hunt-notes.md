# Operator hunt notes (pseudo-logic, not a log schema)

Enea did not publish a signalling-log field list. These checks are written as
questions you can ask of an SS7, Diameter or GTP firewall, a roaming probe, or
an interconnect packet capture. Do not treat the names below as vendor fields.

## SS7 and Diameter (SilentAir-style diversion)

1. Unexpected location updates. An SS7 MAP UpdateLocation, or a Diameter
   Update-Location-Request (ULR), arrives for a subscriber who is already
   registered, from a global title, point code or Diameter origin that is not
   in your approved roaming-partner list, or that belongs to a partner you do
   not expect to serve that IMSI range.
2. Inconsistent answers. After a location update, later uninitiated
   transactions (SMS or call delivery) to the same serving address are
   ignored, aborted, or answered twice. Enea saw all three behaviours on
   SilentAir-controlled nodes, which is not how a normal intercept node
   behaves.
3. Burst then silence. A short burst of location updates, identifier
   harvesting (SRI-SM, RestoreData, SendAuthenticationInfo, or Diameter AIR)
   or a small number of location queries (ATI, Diameter IDR), then weeks or
   months of quiet, is closer to Enea's SilentAir mix than to a commercial
   surveillance firm's usual pattern (mostly harvest and location, little
   interception).
4. Silent SMS. A large volume of silent (class 0 / "type 0") short messages,
   often submitted through an interim SMSC rather than delivered directly,
   especially at night towards Taiwanese number ranges, or used as a test
   shortly after an UpdateLocation. Bodies may look like generic English
   wellness slogans. A hit is a lead, not proof of SilentAir.

Industry starting points, not a complete defence: GSMA FS.11 (SS7) and FS.19
(Diameter) category filtering, SMS home routing, and treating the IPX as
untrusted. Enea's advice is to go beyond those basics and to share events
with GTP and IT security tools.

## GTP (LIMINAL PANDA / GTPDoor)

1. GTP-C. Covert command and control in GTP-C, historically on Echo Request
   style messages, used to start or stop a tunnel, run a command, or check
   that an implant is still alive. Enea blocked this class of traffic from
   the first quarter of 2026.
2. GTP-U. Short-lived GTP-U tunnels between operators that do not match a
   normal roaming data session, especially a setup, a burst of inner traffic,
   and a teardown in under about 21 minutes (the median Enea observed; a few
   lasted 24 hours or more). GTPDoor v3 hides commands deeper in the GTP-U
   packet, often as a T-PDU with an inner IP payload, and Enea believes it is
   used mainly as a backup.
3. Cross-protocol. A GTP-U tunnel attempt from a node or operator shortly
   after unusual SS7 or Diameter activity on the same interconnect is worth
   a joint review. Enea sometimes saw that sequence, and sometimes did not.
4. Host. On IPX-facing Linux hosts, a libpcap listener that does not show in
   netstat or lsof is the detection gap Enea noted for GTPDoor v3. Also
   search for the published sample MD5s (see the Sigma rule in this pack),
   unexpected SSH from signalling hosts, and tools Enea associated with
   LIMINAL PANDA (SGSNemu, EchoBackdoor, SIGTRANslator, Cordscan) if you have
   a binary or process inventory. Absence of a hash is not absence of the
   actor.

Share GTP-C and GTP-U firewall events with SS7 and Diameter defences. Enea's
point is that one protocol on its own often looks too small to act on.
