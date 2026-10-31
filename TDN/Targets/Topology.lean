import TDN.Semantics.Paths

namespace TDN.Targets

/-- RG-034 in declared untrusted transport. External Black connectivity may be
mediated by a network and an intervening firewall; the source does not require a
single direct edge in the otherwise branch. Inner Gray connectivity likewise
permits ordinary intervening switches. -/
def msc_outer_firewall_placement {Node : Type}
    (publicInternet grayFirewallRequired : Bool)
    (edge grayConnection : Node → Node → Prop)
    (outer firewall black grayFirewall inner : Node → Prop)
    (insideAttachment outsideAttachment externalBlackConnection : Node → Node → Prop) : Prop :=
  (if publicInternet then
    ∀ o, outer o → ∃ f b, firewall f ∧ black b ∧
      insideAttachment o f ∧ outsideAttachment f b
   else ∀ o, outer o → ∃ b, black b ∧ externalBlackConnection o b) ∧
  (∀ o b, outer o → black b →
    ¬ Relation.ReflTransGen (Paths.Avoiding edge firewall) o b) ∧
  (if grayFirewallRequired then
    ∀ o, outer o → ∃ g, grayFirewall g ∧ grayConnection o g
   else ∀ o, outer o → ∃ i, inner i ∧ grayConnection o i)

/-- Rejected-model diagnostic: additionally treating every external Black
connection as one direct edge contradicts the firewall cut. That strengthening is
not imposed by the source or by `msc_outer_firewall_placement`. -/
theorem rejected_direct_edge_strengthening_conflicts {Node : Type}
    (grayFirewallRequired : Bool) (edge grayConnection : Node → Node → Prop)
    (outer firewall black grayFirewall inner : Node → Prop)
    (insideAttachment outsideAttachment externalBlackConnection : Node → Node → Prop)
    (wire : ∀ a b, externalBlackConnection a b → edge a b)
    (blackNotFirewall : ∀ b, black b → ¬ firewall b)
    (o : Node) (present : outer o)
    (literal : msc_outer_firewall_placement false grayFirewallRequired edge grayConnection
      outer firewall black grayFirewall inner insideAttachment outsideAttachment externalBlackConnection) : False := by
  obtain ⟨b, hb, attachment⟩ := literal.1 o present
  exact literal.2.1 o b present hb
    (Relation.ReflTransGen.single ⟨wire o b attachment, blackNotFirewall b hb⟩)

end TDN.Targets
