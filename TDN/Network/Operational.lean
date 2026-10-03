import TDN.Network.IPv4

/-!
Typed observations retain operational evidence without asserting its truth.
Every address, interface, route, and policy belongs to the sampled device named
by the containing record. `none` means the observation was unavailable or failed.
An empty observed list is distinct from a missing observation. The records have
no dependency on MSC site names, security levels, device roles, or snapshots.
-/
namespace TDN.Network

structure AddressMetadata where
  network : Prefix
  dynamic : Bool
  validLifetime : Nat
  preferredLifetime : Nat
  deriving DecidableEq, BEq, Repr

structure ObservedInterface where
  name : String
  index : Nat
  peerIndex : Option Nat
  mtu : Nat
  up : Bool
  carrier : Bool
  mac : String
  master : String
  addresses : List Prefix
  addressMetadata : Option (List AddressMetadata) := none
  deriving DecidableEq, BEq, Repr

structure FibRoute where
  destination : Prefix
  gateway : Option UInt32
  output : String
  table : Nat
  kind : String
  protocol : String
  metric : Nat
  preferredSource : Option UInt32
  /-- Scope and next-hop object identity accompany the expanded route. The
  selected importer requires an explicit output and gateway for a next-hop ID. -/
  scope : String := "global"
  nextHopId : Option Nat := none
  deriving DecidableEq, BEq, Repr

structure RoutingRule where
  priority : Nat
  source : Prefix
  table : Nat
  deriving DecidableEq, BEq, Repr

structure XfrmPolicy where
  source : Prefix
  destination : Prefix
  direction : String
  priority : Nat
  tunnelSource : UInt32
  tunnelDestination : UInt32
  reqid : Nat
  mode : String
  protocol : String
  /-- Zero is the kernel wildcard. A nonzero template SPI pins SA selection. -/
  spi : Nat := 0
  deriving DecidableEq, BEq, Repr

structure XfrmState where
  source : UInt32
  destination : UInt32
  spi : Nat
  reqid : Nat
  mode : String
  protocol : String
  algorithm : String
  integrityBits : Nat
  replayWindow : Nat
  hardLifetimeSeconds : Nat
  udpEncapsulation : Bool
  udpSourcePort : Option Nat
  udpDestinationPort : Option Nat
  tfcPadding : Nat
  /-- The restricted interpretation supports zero flags or AF_UNSPEC only.
  The decimal value decodes iproute2's displayed eight-bit binary mask. -/
  flags : Nat := 0
  udpOriginalAddress : Option UInt32 := none
  deriving DecidableEq, BEq, Repr

structure ObservedSwitch where
  ports : List String
  bridge : String
  failMode : String
  controllers : List String
  normalOnly : Bool
  vlanConfigured : Bool
  deriving DecidableEq, BEq, Repr

structure OperationalSnapshot where
  device : String
  observedAt : String
  interfaces : Option (List ObservedInterface)
  routes : Option (List FibRoute)
  routingRules : Option (List RoutingRule)
  forwarding : Option Bool
  policies : Option (List XfrmPolicy)
  states : Option (List XfrmState)
  switching : Option ObservedSwitch
  clockEpoch : Option Nat
  resolverServers : Option (List UInt32)
  processes : Option (List String)
  startup : Option String
  deriving DecidableEq, BEq, Repr

end TDN.Network
