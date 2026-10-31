# Enterprise Gray annex table obligations

The source contains 75 rows across Tables 8–13. Each row uses a table-scoped key because EG-AR-25 and EG-AR-26 are reused for different requirements. The index records open construction work; it does not establish annex compliance.

| Table | Capability section | Rows |
| --- | --- | ---: |
| 8 | general | 23 |
| 9 | multiple capability packages | 5 |
| 10 | centralized management | 21 |
| 11 | scalability | 23 |
| 12 | site survivability | 2 |
| 13 | testing | 1 |

The original table text below retains its threshold/objective designation and alternative references. Narrative requirements and delegated annexes remain additional obligations. Optional management does not become a premise of management-free data-path proofs.

## EG-v1.2.0-T08-EG-FW-1

PDF pages: 30

```text
EG-FW-1 The Gray Firewall must only accept
management traffic on the physical ports
connected to the Gray Management
Network and/or EG Network.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Define the actual traffic/address/interface condition, preserve explicit control-service exceptions, and bind local rule checks plus required positive traffic.

## EG-v1.2.0-T08-EG-FW-2

PDF pages: 30

```text
EG-FW-2 The Gray Firewall must only permit
packets whose source and destination IP
addresses match the external interfaces of
the Encryption Components supporting
the Red Network and EG Network of the
same classification level and internal
interface of the Encryption Components
CSfC Solution.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Define the actual traffic/address/interface condition, preserve explicit control-service exceptions, and bind local rule checks plus required positive traffic.

## EG-v1.2.0-T08-EG-FW-3

PDF pages: 30

```text
EG-FW-3 The Gray Firewall’s outward interface
must block all packets whose source
address does not match a list of addresses
or address ranges known to be reachable
from the interface on which the packet
was received.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Define the actual traffic/address/interface condition, preserve explicit control-service exceptions, and bind local rule checks plus required positive traffic.

## EG-v1.2.0-T08-EG-FW-4

PDF pages: 30

```text
EG-FW-4 The Gray Firewall must deny all traffic on
the outward interface that is not explicitly
allowed.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Define the actual traffic/address/interface condition, preserve explicit control-service exceptions, and bind local rule checks plus required positive traffic.

## EG-v1.2.0-T08-EG-FW-5

PDF pages: 30

```text
EG-FW-5 The Gray Firewall must block all traffic
routed to and between two or more Inner
VPN Gateways of different classification
levels.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Define the actual traffic/address/interface condition, preserve explicit control-service exceptions, and bind local rule checks plus required positive traffic.

## EG-v1.2.0-T08-EG-FW-6

PDF pages: 30

```text
EG-FW-6 Remote administration of the Gray
Firewall from the Gray Management
Network and EG Networks must only use
SSHv2, IPsec, or TLS.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Define the actual traffic/address/interface condition, preserve explicit control-service exceptions, and bind local rule checks plus required positive traffic.

## EG-v1.2.0-T08-EG-FW-7

PDF pages: 30

```text
EG-FW-7 The Gray Firewall must permit IKE, IPsec,
or TLS traffic between EUDs and
Encryption Components.
T=O MA, WLAN
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Formalize the source condition individually and identify its complete applicability and concrete evidence.

## EG-v1.2.0-T08-EG-FW-8

PDF pages: 30

```text
EG-FW-8 The Gray Firewall must allow HTTP traffic
between the Authentication Server and
the Gray CDP or OCSP Responder.
T EG-FW-9
and
EG-FW-10
All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Define the actual traffic/address/interface condition, preserve explicit control-service exceptions, and bind local rule checks plus required positive traffic.

## EG-v1.2.0-T08-EG-FW-9

PDF pages: 30

```text
EG-FW-9 The Gray Firewall/Encryption Component
must allow HTTP traffic between the
Authentication Server and the Gray CDP
or OCSP Responder.
O EG-FW-8 All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Define the actual traffic/address/interface condition, preserve explicit control-service exceptions, and bind local rule checks plus required positive traffic.

## EG-v1.2.0-T08-EG-FW-10

PDF pages: 30, 31

```text
EG-FW-10 The Gray Firewall must allow HTTP
responses from the Gray CDP or OCSP
Responder to the Authentication Server
that contains a well-formed CRL per IETF
O EG-FW-8 All25
Req # Requirement Description Threshold/
Objective Alternative Capability Package
RFC 5280 or OCSP Response per RFC 6960
and block all other HTTP responses.
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Define the actual traffic/address/interface condition, preserve explicit control-service exceptions, and bind local rule checks plus required positive traffic.

## EG-v1.2.0-T08-EG-FW-11

PDF pages: 31

```text
EG-FW-11 The Gray Firewall’s inward interface must
block all packets whose source address
does not match a list of addresses or
address ranges known to be reachable
from the interface on which the packet
was received.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Define the actual traffic/address/interface condition, preserve explicit control-service exceptions, and bind local rule checks plus required positive traffic.

## EG-v1.2.0-T08-EG-FW-12

PDF pages: 31

```text
EG-FW-12 The Gray Firewall’s inward interface must
deny all traffic that is not explicitly
allowed.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Define the actual traffic/address/interface condition, preserve explicit control-service exceptions, and bind local rule checks plus required positive traffic.

## EG-v1.2.0-T08-EG-FW-13

PDF pages: 31

```text
EG-FW-13 The Gray Firewall must allow control
plane traffic between the Outer
Encryption Component, Gray Firewall,
Gray Management Network, and EG
Network (e.g., NTP, Dynamic Host
Configuration Protocol, and DNS).
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Define the actual traffic/address/interface condition, preserve explicit control-service exceptions, and bind local rule checks plus required positive traffic.

## EG-v1.2.0-T08-EG-FW-14

PDF pages: 31

```text
EG-FW-14 A Gray Firewall, Outer Encryption
Component, and Gray Encryption
Component must be administered from a
workstation designated for managing Gray
Components which resides on the local
Gray Management or EG Network.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Formalize the source condition individually and identify its complete applicability and concrete evidence.

## EG-v1.2.0-T08-EG-FW-15

PDF pages: 31

```text
EG-FW-15 Remote administration of all Gray
components must be done using SSHv2,
IPsec, or TLS with the appropriate CNSA
suite for the highest classification of the
solution. Encryption provided by the EG
Network does not fulfill this requirement.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Formalize the source condition individually and identify its complete applicability and concrete evidence.

## EG-v1.2.0-T08-EG-AR-1

PDF pages: 31

```text
EG-AR-1 All Gray Management Services and
Enterprise Gray Services must go through
a firewall to access and communicate with
the Outer Encryption Component, Gray
Firewall, and Gray Encryption Component.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Formalize the source condition individually and identify its complete applicability and concrete evidence.

## EG-v1.2.0-T08-EG-AR-2

PDF pages: 31

```text
EG-AR-2 The time servers that serve network time
to Gray Management and Red
Management must use a secure protocol
to maintain the authenticity and integrity
of the network time to clients.
O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Formalize the source condition individually and identify its complete applicability and concrete evidence.

## EG-v1.2.0-T08-EG-AR-3

PDF pages: 31, 32

```text
EG-AR-3 The DNS servers used on the Gray Data,
Gray Management, and Red Management
Networks must use DNSSEC to secure and
O All26
Req # Requirement Description Threshold/
Objective Alternative Capability Package
maintain the authenticity and integrity of
the domain record to clients.
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Formalize the source condition individually and identify its complete applicability and concrete evidence.

## EG-v1.2.0-T08-EG-AR-4

PDF pages: 32

```text
EG-AR-4 The Outer Encryption Component must be
configured to not route between the inner
interfaces if there is more than one.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Formalize the source condition individually and identify its complete applicability and concrete evidence.

## EG-v1.2.0-T08-EG-AR-5

PDF pages: 32

```text
EG-AR-5 The authentication service that
authenticates EG and/or Gray
Management administrators must be
separate from the EUD and Encryption
Components.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Formalize the source condition individually and identify its complete applicability and concrete evidence.

## EG-v1.2.0-T08-EG-PS-1

PDF pages: 32

```text
EG-PS-1 The Gray Firewall must be chosen from
the list of Traffic Filtering Firewalls on the
CSfC Components List.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Separate product/approval provenance from technical placement or mechanism facts; no approval is inferred from emulation.

## EG-v1.2.0-T08-EG-AR-25

PDF pages: 32

```text
EG-AR-25 The Gray Management Network must be
used exclusively for all management of the
Outer Encryption Component, Gray
Firewall, Gray Encryption Component, if
present, and Solution Components within
the Gray Network.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Formalize the source condition individually and identify its complete applicability and concrete evidence.

## EG-v1.2.0-T08-EG-AR-26

PDF pages: 32

```text
EG-AR-26 All solution components (Firewalls, WLAN
Access Systems, VPN Gateways,
Authentication Servers, and EUDs) must
use software and firmware signing
algorithms in Table 4.
O Optional All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Formalize the source condition individually and identify its complete applicability and concrete evidence.

## EG-v1.2.0-T09-EG-AR-6

PDF pages: 32

```text
EG-AR-6 Inherit all security requirements of the
CPs that are being integrated together.
If the CPs have different requirements
accept the one with the higher security
posture.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Formalize the source condition individually and identify its complete applicability and concrete evidence.

## EG-v1.2.0-T09-EG-AR-7

PDF pages: 32, 33

```text
EG-AR-7 An Outer Firewall is required between
the Outer Encryption Component and
the Black Network.
T=O MA/MSC 27
Req # Requirement Description Threshold/
Objective Alternative Capability Package
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Formalize the source condition individually and identify its complete applicability and concrete evidence.

## EG-v1.2.0-T09-EG-AR-8

PDF pages: 33

```text
EG-AR-8 The Outer Firewall must not have a
physical or logical connection to the Gray
Management Network or EG
Management Network.
T=O MA/MSC
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Formalize the source condition individually and identify its complete applicability and concrete evidence.

## EG-v1.2.0-T09-EG-AR-9

PDF pages: 33

```text
EG-AR-9 EUDs provisioned for an MA solution
must only be used for an MA solution,
and not used to access any resources
other than the Red Network it
communicates with via two layers of
encryption.
T=O MA
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Formalize the source condition individually and identify its complete applicability and concrete evidence.

## EG-v1.2.0-T09-EG-AR-10

PDF pages: 33

```text
EG-AR-10 EUDs provisioned for a Campus WLAN
solution must only be used for a WLAN
solution and not used to access any
resources other than the Red Network it
communicates with via two layers of
encryption.
T=O WLAN
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Formalize the source condition individually and identify its complete applicability and concrete evidence.

## EG-v1.2.0-T10-EG-FW-16

PDF pages: 33

```text
EG-FW-16 The Gray Firewall must be used as the
Inner Encryption Component for the EG
Network.
T EG-FW-17 All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Bind selected Gray encryption arrangement, management/data tunnels, processing order, split-tunnel prevention, MTU and selected algorithm branch; preserve source alternatives.

## EG-v1.2.0-T10-EG-FW-17

PDF pages: 33

```text
EG-FW-17 If the AO deems it necessary, a separate
Gray Encryption Component must be used
to service the EG Network.
O EG-FW-16 All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Bind selected Gray encryption arrangement, management/data tunnels, processing order, split-tunnel prevention, MTU and selected algorithm branch; preserve source alternatives.

## EG-v1.2.0-T10-EG-FW-18

PDF pages: 33, 34

```text
EG-FW-18 The Gray Encryption Component and
Outer Encryption Components must
either: come from different
manufacturers, where neither
manufacturer is a subsidiary of the other;
or be two different products from the
same manufacturer, where NSA has
determined that the two products meet
the CSfC criteria for implementation
independence.
T=O All28
Req # Requirement Description Threshold/
Objective Alternative Capability Package
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Separate product/approval provenance from technical placement or mechanism facts; no approval is inferred from emulation.

## EG-v1.2.0-T10-EG-FW-19

PDF pages: 34

```text
EG-FW-19 The Gray Firewall/Encryption Component
at each site provides the inner layer of
encryption and the Outer Encryption
Component provides the outer layer of
encryption to protect Gray Management
traffic between sites.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Bind selected Gray encryption arrangement, management/data tunnels, processing order, split-tunnel prevention, MTU and selected algorithm branch; preserve source alternatives.

## EG-v1.2.0-T10-EG-FW-20

PDF pages: 34

```text
EG-FW-20 The Gray Firewall/Encryption Component
must not permit split-tunneling.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Bind selected Gray encryption arrangement, management/data tunnels, processing order, split-tunnel prevention, MTU and selected algorithm branch; preserve source alternatives.

## EG-v1.2.0-T10-EG-FW-21

PDF pages: 34

```text
EG-FW-21 The Gray Firewall/Encryption Component
must use Tunnel mode IPsec or Transport
mode IPsec with an associated IP
tunneling protocol (i.e. Generic Routing
Encapsulation), authorized TLS
deployment, or MACsec.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Bind selected Gray encryption arrangement, management/data tunnels, processing order, split-tunnel prevention, MTU and selected algorithm branch; preserve source alternatives.

## EG-v1.2.0-T10-EG-FW-22

PDF pages: 34

```text
EG-FW-22 The Gray Firewall/Encryption Component
must meet all CSfC requirements for an
Encryption Component.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Bind selected Gray encryption arrangement, management/data tunnels, processing order, split-tunnel prevention, MTU and selected algorithm branch; preserve source alternatives.

## EG-v1.2.0-T10-EG-FW-23

PDF pages: 34

```text
EG-FW-23 The Gray Firewall/Encryption Component
must form a Gray Management VPN
tunnel with other Gray
Firewall/Encryption Components that
allows routing between their Gray
Management Networks forming the EG
Network.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Bind selected Gray encryption arrangement, management/data tunnels, processing order, split-tunnel prevention, MTU and selected algorithm branch; preserve source alternatives.

## EG-v1.2.0-T10-EG-FW-24

PDF pages: 34

```text
EG-FW-24 If the AO deems necessary, then the Gray
Firewall/Encryption Component may form
a Gray Data VPN tunnel between itself
and other Gray Firewall/Encryption
Components allowing for routing to
happen between Gray Data Networks.
O Optional All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Bind selected Gray encryption arrangement, management/data tunnels, processing order, split-tunnel prevention, MTU and selected algorithm branch; preserve source alternatives.

## EG-v1.2.0-T10-EG-FW-25

PDF pages: 34

```text
EG-FW-25 The packet size for packets leaving the
external interface of the Gray
Firewall/Encryption Component must be
configured to keep the packets from
being fragmented and impacting
performance. This requires proper
configuration of the Maximum
Transmission Unit (MTU) for IPv4 or Path
MTU (PMTU) for IPv6 and should consider
the Outer VPN Gateway MTU/PMTU
values for achievement.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Bind selected Gray encryption arrangement, management/data tunnels, processing order, split-tunnel prevention, MTU and selected algorithm branch; preserve source alternatives.

## EG-v1.2.0-T10-EG-AR-11

PDF pages: 34, 35

```text
EG-AR-11 Two independent layers of CSfC approved
encryption must be used when extending
T=O All29
Req # Requirement Description Threshold/
Objective Alternative Capability Package
Gray Services to other site(s) over an
untrusted network.
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Bind selected Gray encryption arrangement, management/data tunnels, processing order, split-tunnel prevention, MTU and selected algorithm branch; preserve source alternatives.

## EG-v1.2.0-T10-EG-AR-12

PDF pages: 35

```text
EG-AR-12 Requirement has been relocated to the
CSfC Key Management Requirements
Annex.
- - All
```

Construction status: delegated_to_named_key_management_annex.

Next work: Bind selected Gray encryption arrangement, management/data tunnels, processing order, split-tunnel prevention, MTU and selected algorithm branch; preserve source alternatives.

## EG-v1.2.0-T10-EG-AR-13

PDF pages: 35

```text
EG-AR-13 Requirement has been relocated to the
CSfC Key Management Requirements
Annex.
- - All
```

Construction status: delegated_to_named_key_management_annex.

Next work: Bind selected Gray encryption arrangement, management/data tunnels, processing order, split-tunnel prevention, MTU and selected algorithm branch; preserve source alternatives.

## EG-v1.2.0-T10-EG-AR-14

PDF pages: 35

```text
EG-AR-14 Requirement has been relocated to the
CSfC Symmetric Key Management
Requirements Annex.
- - All
```

Construction status: delegated_to_named_key_management_annex.

Next work: Bind selected Gray encryption arrangement, management/data tunnels, processing order, split-tunnel prevention, MTU and selected algorithm branch; preserve source alternatives.

## EG-v1.2.0-T10-EG-AR-15

PDF pages: 35

```text
EG-AR-15 EUDs provisioned for MA and Campus
WLAN solutions must not be used to
connect to the Gray Firewall/Encryption
Component.
T=O MA, WLAN
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Bind selected Gray encryption arrangement, management/data tunnels, processing order, split-tunnel prevention, MTU and selected algorithm branch; preserve source alternatives.

## EG-v1.2.0-T10-EG-PS-2

PDF pages: 35

```text
EG-PS-2 The Gray Encryption Component must be
chosen from the list of IPsec VPN
Gateways on the CSfC Components List.
T=O EG-PS-3 All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Separate product/approval provenance from technical placement or mechanism facts; no approval is inferred from emulation.

## EG-v1.2.0-T10-EG-PS-3

PDF pages: 35

```text
EG-PS-3 The Gray Encryption Component must be
chosen from the list of MACsec Ethernet
Encryptions on the CSfC Components List.
T=O EG-PS-2 All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Separate product/approval provenance from technical placement or mechanism facts; no approval is inferred from emulation.

## EG-v1.2.0-T10-EG-FW-26

PDF pages: 35

```text
EG-FW-26 The VPN Components must use protocols
and algorithms for creating all VPN
tunnels selected from an Algorithm Suite
in Table 5.
T EG-FW-27,
EG-FW-28,
and EG-FW29
All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Bind selected Gray encryption arrangement, management/data tunnels, processing order, split-tunnel prevention, MTU and selected algorithm branch; preserve source alternatives.

## EG-v1.2.0-T10-EG-FW-27

PDF pages: 35

```text
EG-FW-27 All IPsec connections must use IETF
standards compliant with IKE
implementations as specified in
Commercial National Security Algorithm
(CNSA) Suite 2.0 Profile for IPsec (draftguthrie-cnsa2-ipsec-profile) including RFC
9370, RFC 9242 and RFC 7383.
O EG-FW-26 All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Bind selected Gray encryption arrangement, management/data tunnels, processing order, split-tunnel prevention, MTU and selected algorithm branch; preserve source alternatives.

## EG-v1.2.0-T10-EG-FW-28

PDF pages: 35, 36

```text
EG-FW-28 All IPsec connections must use multiple
key exchanges with an initial IKEv2 SA key
exchange and an intermediate IKEv2 key
exchange:
O EG-FW-26 All30
Req # Requirement Description Threshold/
Objective Alternative Capability Package
• IKE_SA_INIT: The IKEv2 SA key
exchange performed in
IKE_SA_INIT must use a CNSA 1.0
key establishment algorithm (as
specified in Table 5)
• IKE_INTERMEDIATE: The IKEv2 SA
key establishment performed in
the IKE_INTERMEDIATE exchange
must use ML-KEM-1024 (as
specified in Table 6)
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Bind selected Gray encryption arrangement, management/data tunnels, processing order, split-tunnel prevention, MTU and selected algorithm branch; preserve source alternatives.

## EG-v1.2.0-T10-EG-FW-29

PDF pages: 36

```text
EG-FW-29 The VPN Components must use
algorithms from the algorithm suite in
Table 6 for all IPsec VPN tunnels, with the
exception of the IKE_SA_INIT exchange.
O EG-FW-26 All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Bind selected Gray encryption arrangement, management/data tunnels, processing order, split-tunnel prevention, MTU and selected algorithm branch; preserve source alternatives.

## EG-v1.2.0-T11-EG-DR-1

PDF pages: 36

```text
EG-DR-1 Dynamic routing is only allowed on the
Gray Firewall/Encryption Component, no
other devices on the network can
perform dynamic routing.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Make dynamic-routing/VRF applicability explicit; check permitted components/interfaces, peer authentication, route separation and most-specific permitted routes against actual route policies.

## EG-v1.2.0-T11-EG-DR-2

PDF pages: 36

```text
EG-DR-2 If dynamic routing protocols are used,
then dynamic routing peer
authentication must be performed
between the Gray Firewalls/Encryption
Components running dynamic routing.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Make dynamic-routing/VRF applicability explicit; check permitted components/interfaces, peer authentication, route separation and most-specific permitted routes against actual route policies.

## EG-v1.2.0-T11-EG-DR-3

PDF pages: 36

```text
EG-DR-3 If dynamic routing protocols are used,
dynamic routing peer authentication
used by the network devices must use an
MD5 hashing algorithm.
T EG-DR-4 All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Make dynamic-routing/VRF applicability explicit; check permitted components/interfaces, peer authentication, route separation and most-specific permitted routes against actual route policies.

## EG-v1.2.0-T11-EG-DR-4

PDF pages: 36, 37

```text
EG-DR-4 If dynamic routing protocols are used,
dynamic routing peer authentication
used by the network devices must use a
SHA-256 hashing algorithm or greater.
O EG-DR-3 All31
Req # Requirement Description Threshold/
Objective Alternative Capability Package
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Make dynamic-routing/VRF applicability explicit; check permitted components/interfaces, peer authentication, route separation and most-specific permitted routes against actual route policies.

## EG-v1.2.0-T11-EG-DR-5

PDF pages: 37

```text
EG-DR-5 If dynamic routing protocols are used, all
network devices participating in dynamic
routing message authentication must use
a strong PSK with at least 256-bits of
entropy for the entire network (Group
Keys).
T EG-DR-6 All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Make dynamic-routing/VRF applicability explicit; check permitted components/interfaces, peer authentication, route separation and most-specific permitted routes against actual route policies.

## EG-v1.2.0-T11-EG-DR-6

PDF pages: 37

```text
EG-DR-6 If dynamic routing protocols are used, all
network devices participating in dynamic
routing message authentication must use
a strong PSK with at least 256-bits of
entropy for every network device (Pointto-point Pre-Shared Keys).
O EG-DR-5 All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Make dynamic-routing/VRF applicability explicit; check permitted components/interfaces, peer authentication, route separation and most-specific permitted routes against actual route policies.

## EG-v1.2.0-T11-EG-DR-7

PDF pages: 37

```text
EG-DR-7 If dynamic routing protocols are used, all
network devices participating in dynamic
routing must only share necessary
routing information about the local Gray
Management Network and other Gray
Management Networks to devices
servicing the Gray Management VPN
tunnels.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Make dynamic-routing/VRF applicability explicit; check permitted components/interfaces, peer authentication, route separation and most-specific permitted routes against actual route policies.

## EG-v1.2.0-T11-EG-DR-8

PDF pages: 37

```text
EG-DR-8 If dynamic routing protocols are used, all
network devices participating in dynamic
routing must only share necessary
routing information about the local Gray
Data Network and other Gray Data
Networks to devices servicing the Gray
Data VPN tunnels.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Make dynamic-routing/VRF applicability explicit; check permitted components/interfaces, peer authentication, route separation and most-specific permitted routes against actual route policies.

## EG-v1.2.0-T11-EG-DR-9

PDF pages: 37

```text
EG-DR-9 If dynamic routing protocols are used, all
network devices performing dynamic
routing must use route filtering on both
inbound and outbound routes stopping
unauthorized routes from being received
or shared and by default all routes must
be blocked.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Make dynamic-routing/VRF applicability explicit; check permitted components/interfaces, peer authentication, route separation and most-specific permitted routes against actual route policies.

## EG-v1.2.0-T11-EG-DR-10

PDF pages: 37

```text
EG-DR-10 If dynamic routing protocols are used,
the network devices performing dynamic
routing must disable dynamic routing on
all interfaces except the interfaces
serving the Gray Management VPN
tunnel and the Gray Data VPN tunnel.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Make dynamic-routing/VRF applicability explicit; check permitted components/interfaces, peer authentication, route separation and most-specific permitted routes against actual route policies.

## EG-v1.2.0-T11-EG-DR-11

PDF pages: 37, 38

```text
EG-DR-11 If dynamic routing protocols are used,
routes must not be shared between the
Gray Management and Data Tunnels.
T=O All 32
Req # Requirement Description Threshold/
Objective Alternative Capability Package
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Make dynamic-routing/VRF applicability explicit; check permitted components/interfaces, peer authentication, route separation and most-specific permitted routes against actual route policies.

## EG-v1.2.0-T11-EG-DR-12

PDF pages: 38

```text
EG-DR-12 If dynamic routing protocols are used,
routes being shared and filtered must be
the most specific routes possible.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Make dynamic-routing/VRF applicability explicit; check permitted components/interfaces, peer authentication, route separation and most-specific permitted routes against actual route policies.

## EG-v1.2.0-T11-EG-AR-16

PDF pages: 38

```text
EG-AR-16 If dynamic routing protocols are used,
then two VRFs must be used to separate
Data and Management traffic.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Make dynamic-routing/VRF applicability explicit; check permitted components/interfaces, peer authentication, route separation and most-specific permitted routes against actual route policies.

## EG-v1.2.0-T11-EG-AR-17

PDF pages: 38

```text
EG-AR-17 Two VRFs must be used to separate Data
and Management traffic.
O Optional All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Make dynamic-routing/VRF applicability explicit; check permitted components/interfaces, peer authentication, route separation and most-specific permitted routes against actual route policies.

## EG-v1.2.0-T11-EG-AR-18

PDF pages: 38

```text
EG-AR-18 If VRFs are used, the Management VRFs
must only contain routing information
about the local Gray Management
network and remote Gray Management
networks.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Make dynamic-routing/VRF applicability explicit; check permitted components/interfaces, peer authentication, route separation and most-specific permitted routes against actual route policies.

## EG-v1.2.0-T11-EG-AR-19

PDF pages: 38

```text
EG-AR-19 If VRFs are used, the Data VRFs must only
contain routing information about the
local Gray Data network and remote Gray
Data networks.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Make dynamic-routing/VRF applicability explicit; check permitted components/interfaces, peer authentication, route separation and most-specific permitted routes against actual route policies.

## EG-v1.2.0-T11-EG-AR-20

PDF pages: 38

```text
EG-AR-20 If VRFs are used, the routes cannot be
exported or imported between the data
and management routing instances.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Make dynamic-routing/VRF applicability explicit; check permitted components/interfaces, peer authentication, route separation and most-specific permitted routes against actual route policies.

## EG-v1.2.0-T11-EG-AR-21

PDF pages: 38

```text
EG-AR-21 If VRFs are used, they are allowed to
import routes from an outside routing
instance as long as they do not allow
sharing of non-authorized routes.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Make dynamic-routing/VRF applicability explicit; check permitted components/interfaces, peer authentication, route separation and most-specific permitted routes against actual route policies.

## EG-v1.2.0-T11-EG-AR-22

PDF pages: 38

```text
EG-AR-22 If dynamic routing protocols are used,
implementers must use one of the
following: Routing Information Protocol
(RIPv2), OSPF, EIGRP, BGP, or IS-IS.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Make dynamic-routing/VRF applicability explicit; check permitted components/interfaces, peer authentication, route separation and most-specific permitted routes against actual route policies.

## EG-v1.2.0-T11-EG-AR-25

PDF pages: 38

```text
EG-AR-25 The VPN Components must use protocols
and algorithms for creating all VPN
tunnels selected from an Algorithm Suite
in Table 5 that are approved to protect
the highest classification level of the Red
Network data.
T EG-AR-26,
EG-AR-27,
and EG-AR28
All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Make dynamic-routing/VRF applicability explicit; check permitted components/interfaces, peer authentication, route separation and most-specific permitted routes against actual route policies.

## EG-v1.2.0-T11-EG-AR-26

PDF pages: 38, 39

```text
EG-AR-26 All IPsec connections must use IETF
standards compliant with IKE
implementations as specified in
Commercial National Security Algorithm
(CNSA) Suite 2.0 Profile for IPsec (draftguthrie-cnsa2-ipsec-profile) including RFC
9370, RFC 9242 and RFC 7383.
O EG-AR-25 All33
Req # Requirement Description Threshold/
Objective Alternative Capability Package
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Make dynamic-routing/VRF applicability explicit; check permitted components/interfaces, peer authentication, route separation and most-specific permitted routes against actual route policies.

## EG-v1.2.0-T11-EG-AR-27

PDF pages: 39

```text
EG-AR-27 All IPsec connections must use multiple
key exchanges with an initial IKEv2 SA key
exchange and an intermediate IKEv2 key
exchange:
• IKE_SA_INIT: The IKEv2 SA key
exchange performed in
IKE_SA_INIT must use a CNSA 1.0
key establishment algorithm (as
specified in Table 5)
• IKE_INTERMEDIATE: The IKEv2 SA
key establishment performed in
the IKE_INTERMEDIATE exchange
must use ML-KEM-1024 (as
specified in Table 6)
O EG-AR-25 All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Make dynamic-routing/VRF applicability explicit; check permitted components/interfaces, peer authentication, route separation and most-specific permitted routes against actual route policies.

## EG-v1.2.0-T11-EG-AR-28

PDF pages: 39

```text
EG-AR-28 The VPN Components must use
algorithms from the algorithm suite in
Table 6 for all IPsec VPN tunnels, with the
exception of the IKE_SA_INIT exchange.
O EG-AR-25 All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Make dynamic-routing/VRF applicability explicit; check permitted components/interfaces, peer authentication, route separation and most-specific permitted routes against actual route policies.

## EG-v1.2.0-T12-EG-AR-23

PDF pages: 39

```text
EG-AR-23 Should a loss of connection occur, a local
implementer must use an authorized
authentication service to authenticate EUDs
and Encryption Components.
T=O All
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Model the selected loss-of-connection case and local authentication/DNS service behavior; finite snapshots alone do not establish every failure schedule.

## EG-v1.2.0-T12-EG-AR-24

PDF pages: 39, 40

```text
EG-AR-24 If the implementing organization requires
site survivability, implementers must use a
Gray Data DNS on the remote site(s) that
mirrors the DNS on the main site. This
allows for EUDs and site-to-site interfaces
to connect to the proper Inner Encryption
Component.
T=O All 34
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Model the selected loss-of-connection case and local authentication/DNS service behavior; finite snapshots alone do not establish every failure schedule.

## EG-v1.2.0-T13-EG-TR-0

PDF pages: 40, 41

```text
EG-TR-0 The organization implementing the annex
must perform all tests listed in EG Testing
Annex and maintain artifacts of the testing
results.
T=O All35
```

Construction status: requires_clause_specific_formalization_and_evidence.

Next work: Resolve the referenced EG Testing Annex and enumerate actual required tests and retained results.
