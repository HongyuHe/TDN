import TDN.Semantics.Paths

namespace TDN.Targets

def msc_outer_firewall_placement {Node : Type}
    (untrustedBlack publicInternet grayFirewallRequired : Bool)
    (edge grayConnection : Node → Node → Prop)
    (outer firewall black grayFirewall inner : Node → Prop)
    (insideAttachment outsideAttachment externalBlackConnection : Node → Node → Prop) : Prop :=
  (publicInternet = true → untrustedBlack = true) ∧
  (∀ a b, insideAttachment a b ∨ outsideAttachment a b ∨ externalBlackConnection a b →
    Relation.ReflTransGen edge a b) ∧
  (if publicInternet then
    ∀ o, outer o → ∃ f b, firewall f ∧ black b ∧
      insideAttachment o f ∧ outsideAttachment f b
   else ∀ o, outer o → ∃ b, black b ∧ externalBlackConnection o b) ∧
  (untrustedBlack = true → ∀ o b, outer o → black b →
    ¬ Relation.ReflTransGen (Paths.Avoiding edge firewall) o b) ∧
  (if grayFirewallRequired then
    ∀ o, outer o → ∃ g, grayFirewall g ∧ grayConnection o g
   else ∀ o, outer o → ∃ i, inner i ∧ grayConnection o i)

theorem outer_firewall_placement_from_local_checks {Node Side : Type}
    {untrusted publicInternet grayRequired : Bool}
    {edge grayConnection : Node → Node → Prop}
    {outer firewall black grayFirewall inner : Node → Prop}
    {inside outside external : Node → Node → Prop}
    (side : Node → Side)
    (internetUntrusted : publicInternet = true → untrusted = true)
    (connections : ∀ a b, inside a b ∨ outside a b ∨ external a b →
      Relation.ReflTransGen edge a b)
    (placement : if publicInternet then
      ∀ o, outer o → ∃ f b, firewall f ∧ black b ∧ inside o f ∧ outside f b
      else ∀ o, outer o → ∃ b, black b ∧ external o b)
    (grayPlacement : if grayRequired then
      ∀ o, outer o → ∃ g, grayFirewall g ∧ grayConnection o g
      else ∀ o, outer o → ∃ i, inner i ∧ grayConnection o i)
    (edgesChecked : untrusted = true → ∀ a b, edge a b →
      ¬ firewall a → ¬ firewall b → side a = side b)
    (outerClear : untrusted = true → ∀ o, outer o → ¬ firewall o)
    (differentSides : untrusted = true → ∀ o b, outer o → black b → side o ≠ side b) :
    msc_outer_firewall_placement untrusted publicInternet grayRequired edge grayConnection
      outer firewall black grayFirewall inner inside outside external := by
  refine ⟨internetUntrusted, connections, placement, ?_, grayPlacement⟩
  intro applies o b ho hb
  exact Paths.no_firewall_free_crossing edge firewall side (edgesChecked applies)
    (outerClear applies o ho) (differentSides applies o b ho hb)

theorem untrusted_outer_connection_has_firewall {Node : Type}
    (untrusted internetSelected grayRequired : Bool)
    (edge grayConnection : Node → Node → Prop)
    (outer firewall black grayFirewall inner : Node → Prop)
    (inside outside external : Node → Node → Prop)
    (conform : msc_outer_firewall_placement untrusted internetSelected grayRequired edge grayConnection
      outer firewall black grayFirewall inner inside outside external)
    (applies : untrusted = true) (o : Node) (present : outer o) :
    ∃ f, firewall f := by
  by_cases internet : internetSelected = true
  · have placement : ∀ o, outer o → ∃ f b, firewall f ∧ black b ∧
        inside o f ∧ outside f b := by simpa [internet] using conform.2.2.1
    obtain ⟨f, b, hf, _⟩ := placement o present
    exact ⟨f, hf⟩
  · have placement : ∀ o, outer o → ∃ b, black b ∧ external o b := by
      simpa [internet] using conform.2.2.1
    obtain ⟨b, hb, connected⟩ := placement o present
    have path := conform.2.1 o b (Or.inr (Or.inr connected))
    apply Classical.byContradiction
    intro absent
    have clear : ∀ f, ¬ firewall f := fun f hf => absent ⟨f, hf⟩
    have avoiding := Paths.path_avoids_absent_firewalls edge firewall clear path
    exact conform.2.2.2.1 applies o b present hb avoiding

theorem rejected_direct_edge_strengthening_conflicts {Node : Type}
    (grayFirewallRequired : Bool) (edge grayConnection : Node → Node → Prop)
    (outer firewall black grayFirewall inner : Node → Prop)
    (insideAttachment outsideAttachment externalBlackConnection : Node → Node → Prop)
    (wire : ∀ a b, externalBlackConnection a b → edge a b)
    (blackNotFirewall : ∀ b, black b → ¬ firewall b)
    (o : Node) (present : outer o)
    (literal : msc_outer_firewall_placement true false grayFirewallRequired edge grayConnection
      outer firewall black grayFirewall inner insideAttachment outsideAttachment externalBlackConnection) : False := by
  obtain ⟨b, hb, attachment⟩ := literal.2.2.1 o present
  exact literal.2.2.2.1 rfl o b present hb
    (Relation.ReflTransGen.single ⟨wire o b attachment, blackNotFirewall b hb⟩)

end TDN.Targets

namespace TDN.Targets

def msc_gray_firewall_path_coverage {Node Label : Type}
    (grayEdge : Node → Node → Prop) (grayFirewall inner management : Node → Prop)
    (level : Node → Label) (highest : Label) (dominates : Label → Label → Prop)
    (filtersIntendedSameLevel physicallyProtected : Node → Prop) : Prop :=
  (∀ a b, inner a → inner b → level a ≠ level b →
    ¬ Relation.ReflTransGen (Paths.Avoiding grayEdge grayFirewall) a b) ∧
  (∀ administrator component, management administrator → inner component →
    level component ≠ highest →
      ¬ Relation.ReflTransGen (Paths.Avoiding grayEdge grayFirewall) administrator component) ∧
  (∀ administrator, management administrator → level administrator = highest) ∧
  (∀ component, inner component → dominates highest (level component)) ∧
  (∀ firewall, grayFirewall firewall →
    filtersIntendedSameLevel firewall ∧ physicallyProtected firewall) ∧
  ((∃ a b, inner a ∧ inner b ∧ level a ≠ level b) → ∃ firewall, grayFirewall firewall)

theorem gray_firewall_paths_from_local_separation {Node Label : Type}
    (grayEdge : Node → Node → Prop) (grayFirewall inner management : Node → Prop)
    (level : Node → Label) (highest : Label) (dominates : Label → Label → Prop)
    (filtersIntendedSameLevel physicallyProtected : Node → Prop)
    (edgesChecked : ∀ a b, grayEdge a b → ¬ grayFirewall a → ¬ grayFirewall b → level a = level b)
    (innerNotFirewall : ∀ component, inner component → ¬ grayFirewall component)
    (managementNotFirewall : ∀ administrator, management administrator → ¬ grayFirewall administrator)
    (managementLevel : ∀ administrator, management administrator → level administrator = highest)
    (highestLevel : ∀ component, inner component → dominates highest (level component))
    (firewallChecks : ∀ firewall, grayFirewall firewall →
      filtersIntendedSameLevel firewall ∧ physicallyProtected firewall)
    (firewallPresent : (∃ a b, inner a ∧ inner b ∧ level a ≠ level b) →
      ∃ firewall, grayFirewall firewall) :
    msc_gray_firewall_path_coverage grayEdge grayFirewall inner management level highest
      dominates filtersIntendedSameLevel physicallyProtected := by
  refine ⟨?_, ?_, managementLevel, highestLevel, firewallChecks, firewallPresent⟩
  · intro a b innerA _ different
    exact Paths.no_firewall_free_crossing grayEdge grayFirewall level edgesChecked
      (innerNotFirewall a innerA) different
  · intro administrator component managed _ different
    apply Paths.no_firewall_free_crossing grayEdge grayFirewall level edgesChecked
      (managementNotFirewall administrator managed)
    rw [managementLevel administrator managed]
    exact Ne.symm different

end TDN.Targets
