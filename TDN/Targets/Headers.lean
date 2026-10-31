import TDN.Semantics.HeaderPolicy

namespace TDN.Targets
open PacketPolicy

structure GatewayHeaderPolicy where
  device : String
  outer : Bool
  external : String
  ipv4Active : Bool
  ipv6Active : Bool
  ipv4OptionsObjective : Bool
  ipv4Rules : List (List Rule)
  ipv6Rules : List (List Rule)
  ipv4ReceiveRules : List (List Rule)
  ipv6ReceiveRules : List (List Rule)
  deriving DecidableEq

def multicast4Low : Nat := 3758096384
def multicast4High : Nat := 4026531839
def multicast6Low : Nat := 338953138925153547590470800371487866880
def multicast6High : Nat := 340282366920938463463374607431768211455

def HeaderCertificate (g : GatewayHeaderPolicy) : Prop :=
  (g.ipv4Active = true → ∀ rs ∈ g.ipv4Rules, ∀ r ∈ rs, r.verdict = .allow → ProtocolGuard ["tcp","udp","esp","icmp"] r) ∧
  (g.ipv6Active = true → ∀ rs ∈ g.ipv6Rules, ∀ r ∈ rs, r.verdict = .allow → ImmediateHeaderGuard [6,17,50,58] r) ∧
  (g.outer = true →
    (g.ipv4Active = true → ∀ rs ∈ g.ipv4ReceiveRules, ∀ r ∈ rs, r.verdict = .allow → UnicastGuard g.external multicast4Low multicast4High r) ∧
    (g.ipv6Active = true → ∀ rs ∈ g.ipv6ReceiveRules, ∀ r ∈ rs, r.verdict = .allow → UnicastGuard g.external multicast6Low multicast6High r) ∧
    (g.ipv4Active = true → g.ipv4OptionsObjective = true → ∀ rs ∈ g.ipv4Rules, ∀ r ∈ rs, r.verdict = .allow → .ipv4HeaderWords 5 ∈ r.atoms))

instance (g : GatewayHeaderPolicy) : Decidable (HeaderCertificate g) := by
  unfold HeaderCertificate
  letI (rs : List Rule) : Decidable (∀ r ∈ rs, r.verdict = .allow → ProtocolGuard ["tcp","udp","esp","icmp"] r) := by infer_instance
  letI (rs : List Rule) : Decidable (∀ r ∈ rs, r.verdict = .allow → ImmediateHeaderGuard [6,17,50,58] r) := by infer_instance
  letI (rs : List Rule) : Decidable (∀ r ∈ rs, r.verdict = .allow → UnicastGuard g.external multicast4Low multicast4High r) := by infer_instance
  letI (rs : List Rule) : Decidable (∀ r ∈ rs, r.verdict = .allow → UnicastGuard g.external multicast6Low multicast6High r) := by infer_instance
  letI (rs : List Rule) : Decidable (∀ r ∈ rs, r.verdict = .allow → .ipv4HeaderWords 5 ∈ r.atoms) := by infer_instance
  infer_instance

def msc_ip_header_and_multicast_filtering (gateways : List GatewayHeaderPolicy) : Prop :=
  gateways ≠ [] ∧ ∀ g ∈ gateways,
    (g.ipv4Active = true → ∀ rs ∈ g.ipv4Rules, ∀ p, Accepts rs p → p.protocol ∈ ["tcp","udp","esp","icmp"]) ∧
    (g.ipv6Active = true → ∀ rs ∈ g.ipv6Rules, ∀ p, Accepts rs p → p.ipv6NextHeader ∈ [6,17,50,58]) ∧
    (g.outer = true →
      (g.ipv4Active = true → ∀ rs ∈ g.ipv4ReceiveRules, ∀ p, Accepts rs p → p.ingress = g.external → ¬ (multicast4Low ≤ p.destination ∧ p.destination ≤ multicast4High)) ∧
      (g.ipv6Active = true → ∀ rs ∈ g.ipv6ReceiveRules, ∀ p, Accepts rs p → p.ingress = g.external → ¬ (multicast6Low ≤ p.destination ∧ p.destination ≤ multicast6High)) ∧
      (g.ipv4Active = true → g.ipv4OptionsObjective = true → ∀ rs ∈ g.ipv4Rules, ∀ p, Accepts rs p → p.ipv4HeaderWords = 5))

theorem header_certificates_suffice (gateways : List GatewayHeaderPolicy)
    (nonempty : gateways ≠ []) (checked : ∀ g ∈ gateways, HeaderCertificate g) :
    msc_ip_header_and_multicast_filtering gateways := by
  refine ⟨nonempty, ?_⟩
  intro g hg
  obtain ⟨v4, v6, outer⟩ := checked g hg
  refine ⟨?_, ?_, ?_⟩
  · intro active rs member p accepted
    exact accepted_protocol rs _ (v4 active rs member) p accepted
  · intro active rs member p accepted
    exact accepted_immediate_header rs _ (v6 active rs member) p accepted
  · intro isOuter
    obtain ⟨uni4, uni6, options⟩ := outer isOuter
    refine ⟨?_, ?_, ?_⟩
    · intro active rs member p accepted incoming
      exact accepted_external_unicast rs g.external _ _ (uni4 active rs member) p accepted incoming
    · intro active rs member p accepted incoming
      exact accepted_external_unicast rs g.external _ _ (uni6 active rs member) p accepted incoming
    · intro active selected rs member p accepted
      exact accepted_header_words rs 5 (options active selected rs member) p accepted

end TDN.Targets
