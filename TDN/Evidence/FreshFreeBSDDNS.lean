import TDN.Import.Command
import TDN.Targets.StatefulDNS

namespace TDN.Imported.FreshFreeBSDDNS
open Targets.StatefulDNS

tdn_data guest0Addresses : List LocalAddress from "../../evidence/lean/FreshFreeBSDDNS.json" ["TDN.Imported.FreshFreeBSDDNS.guest0Addresses"]

tdn_data guest0Guards : List Guard from "../../evidence/lean/FreshFreeBSDDNS.json" ["TDN.Imported.FreshFreeBSDDNS.guest0Guards"]

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

tdn_data guest1Addresses : List LocalAddress from "../../evidence/lean/FreshFreeBSDDNS.json" ["TDN.Imported.FreshFreeBSDDNS.guest1Addresses"]

tdn_data guest1Guards : List Guard from "../../evidence/lean/FreshFreeBSDDNS.json" ["TDN.Imported.FreshFreeBSDDNS.guest1Guards"]

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
