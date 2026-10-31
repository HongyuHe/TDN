import TDN.Targets.StatefulDNS

namespace TDN.Imported.FreshFreeBSDDNS
open Targets.StatefulDNS

def guest0Addresses : List LocalAddress := [{ address := "10.0.2.15", scopeInterface := none }, { address := "fe80::5054:76ff:fe03:10", scopeInterface := some "vtnet0" }, { address := "fec0::5054:76ff:fe03:10", scopeInterface := none }, { address := "172.28.90.1", scopeInterface := none }, { address := "fe80::5054:76ff:fe03:11", scopeInterface := some "vtnet1" }, { address := "127.0.0.1", scopeInterface := none }, { address := "::1", scopeInterface := none }, { address := "fe80::1", scopeInterface := some "lo0" }, { address := "10.1.1.1", scopeInterface := none }, { address := "fe80::6f:60ff:fe3f:1bb7", scopeInterface := some "vtnet2" }, { address := "10.100.1.2", scopeInterface := none }]
def guest0Guards : List Guard := [{ binding := { address := "fe80::5054:76ff:fe03:10", scopeInterface := some "vtnet0" }, protocol := "tcp" }, { binding := { address := "fec0::5054:76ff:fe03:10", scopeInterface := none }, protocol := "tcp" }, { binding := { address := "fe80::5054:76ff:fe03:11", scopeInterface := some "vtnet1" }, protocol := "tcp" }, { binding := { address := "::1", scopeInterface := none }, protocol := "tcp" }, { binding := { address := "fe80::1", scopeInterface := some "lo0" }, protocol := "tcp" }, { binding := { address := "fe80::6f:60ff:fe3f:1bb7", scopeInterface := some "vtnet2" }, protocol := "tcp" }, { binding := { address := "fe80::5054:76ff:fe03:10", scopeInterface := some "vtnet0" }, protocol := "udp" }, { binding := { address := "fec0::5054:76ff:fe03:10", scopeInterface := none }, protocol := "udp" }, { binding := { address := "fe80::5054:76ff:fe03:11", scopeInterface := some "vtnet1" }, protocol := "udp" }, { binding := { address := "::1", scopeInterface := none }, protocol := "udp" }, { binding := { address := "fe80::1", scopeInterface := some "lo0" }, protocol := "udp" }, { binding := { address := "fe80::6f:60ff:fe3f:1bb7", scopeInterface := some "vtnet2" }, protocol := "udp" }, { binding := { address := "10.0.2.15", scopeInterface := none }, protocol := "tcp" }, { binding := { address := "172.28.90.1", scopeInterface := none }, protocol := "tcp" }, { binding := { address := "127.0.0.1", scopeInterface := none }, protocol := "tcp" }, { binding := { address := "10.1.1.1", scopeInterface := none }, protocol := "tcp" }, { binding := { address := "10.100.1.2", scopeInterface := none }, protocol := "tcp" }, { binding := { address := "10.0.2.15", scopeInterface := none }, protocol := "udp" }, { binding := { address := "172.28.90.1", scopeInterface := none }, protocol := "udp" }, { binding := { address := "127.0.0.1", scopeInterface := none }, protocol := "udp" }, { binding := { address := "10.1.1.1", scopeInterface := none }, protocol := "udp" }, { binding := { address := "10.100.1.2", scopeInterface := none }, protocol := "udp" }]
lemma guest0_coverage : ∀ address ∈ guest0Addresses,
    ∀ protocol ∈ ["tcp", "udp"],
    { binding := address, protocol := protocol } ∈ guest0Guards := by
  unfold guest0Addresses guest0Guards
  decide

theorem guest0_dns_denied_after_any_history
    {events : List (Option Packet)} {cache : List Unit}
    (run : (StatefulFilter.lts (policy guest0Guards)).MTr [] events cache)
    (packet : Packet) (request : ConventionalLocalRequest guest0Addresses packet) :
    StatefulFilter.verdict (policy guest0Guards) cache packet = .deny :=
  local_dns_denied_after_any_history _ _ guest0_coverage run packet request

theorem guest0_enabled_egress_dns_denial
    {events : List (Option Packet)} {cache : List Unit}
    (run : (StatefulFilter.lts (policy guest0Guards)).MTr [] events cache)
    (packet : Packet) (request : ConventionalLocalRequest guest0Addresses packet) :
    hookVerdict true [] guest0Guards cache packet = .deny :=
  enabled_egress_denies_local_dns _ _ guest0_coverage run packet request

def guest1Addresses : List LocalAddress := [{ address := "10.0.2.15", scopeInterface := none }, { address := "fe80::5054:76ff:fe03:1010", scopeInterface := some "vtnet0" }, { address := "fec0::5054:76ff:fe03:1010", scopeInterface := none }, { address := "172.28.90.2", scopeInterface := none }, { address := "fe80::5054:76ff:fe03:1011", scopeInterface := some "vtnet1" }, { address := "127.0.0.1", scopeInterface := none }, { address := "::1", scopeInterface := none }, { address := "fe80::1", scopeInterface := some "lo0" }, { address := "10.2.1.1", scopeInterface := none }, { address := "fe80::2c:94ff:fe19:497", scopeInterface := some "vtnet2" }, { address := "10.200.1.2", scopeInterface := none }]
def guest1Guards : List Guard := [{ binding := { address := "fe80::5054:76ff:fe03:1010", scopeInterface := some "vtnet0" }, protocol := "tcp" }, { binding := { address := "fec0::5054:76ff:fe03:1010", scopeInterface := none }, protocol := "tcp" }, { binding := { address := "fe80::5054:76ff:fe03:1011", scopeInterface := some "vtnet1" }, protocol := "tcp" }, { binding := { address := "::1", scopeInterface := none }, protocol := "tcp" }, { binding := { address := "fe80::1", scopeInterface := some "lo0" }, protocol := "tcp" }, { binding := { address := "fe80::2c:94ff:fe19:497", scopeInterface := some "vtnet2" }, protocol := "tcp" }, { binding := { address := "fe80::5054:76ff:fe03:1010", scopeInterface := some "vtnet0" }, protocol := "udp" }, { binding := { address := "fec0::5054:76ff:fe03:1010", scopeInterface := none }, protocol := "udp" }, { binding := { address := "fe80::5054:76ff:fe03:1011", scopeInterface := some "vtnet1" }, protocol := "udp" }, { binding := { address := "::1", scopeInterface := none }, protocol := "udp" }, { binding := { address := "fe80::1", scopeInterface := some "lo0" }, protocol := "udp" }, { binding := { address := "fe80::2c:94ff:fe19:497", scopeInterface := some "vtnet2" }, protocol := "udp" }, { binding := { address := "10.0.2.15", scopeInterface := none }, protocol := "tcp" }, { binding := { address := "172.28.90.2", scopeInterface := none }, protocol := "tcp" }, { binding := { address := "127.0.0.1", scopeInterface := none }, protocol := "tcp" }, { binding := { address := "10.2.1.1", scopeInterface := none }, protocol := "tcp" }, { binding := { address := "10.200.1.2", scopeInterface := none }, protocol := "tcp" }, { binding := { address := "10.0.2.15", scopeInterface := none }, protocol := "udp" }, { binding := { address := "172.28.90.2", scopeInterface := none }, protocol := "udp" }, { binding := { address := "127.0.0.1", scopeInterface := none }, protocol := "udp" }, { binding := { address := "10.2.1.1", scopeInterface := none }, protocol := "udp" }, { binding := { address := "10.200.1.2", scopeInterface := none }, protocol := "udp" }]
lemma guest1_coverage : ∀ address ∈ guest1Addresses,
    ∀ protocol ∈ ["tcp", "udp"],
    { binding := address, protocol := protocol } ∈ guest1Guards := by
  unfold guest1Addresses guest1Guards
  decide

theorem guest1_dns_denied_after_any_history
    {events : List (Option Packet)} {cache : List Unit}
    (run : (StatefulFilter.lts (policy guest1Guards)).MTr [] events cache)
    (packet : Packet) (request : ConventionalLocalRequest guest1Addresses packet) :
    StatefulFilter.verdict (policy guest1Guards) cache packet = .deny :=
  local_dns_denied_after_any_history _ _ guest1_coverage run packet request

theorem guest1_enabled_egress_dns_denial
    {events : List (Option Packet)} {cache : List Unit}
    (run : (StatefulFilter.lts (policy guest1Guards)).MTr [] events cache)
    (packet : Packet) (request : ConventionalLocalRequest guest1Addresses packet) :
    hookVerdict true [] guest1Guards cache packet = .deny :=
  enabled_egress_denies_local_dns _ _ guest1_coverage run packet request

end TDN.Imported.FreshFreeBSDDNS
