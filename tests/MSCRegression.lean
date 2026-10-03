import TDN

/-!
# Regression witnesses for the assumptions behind the proofs

The first two examples deliberately violate a security premise. They show why
the graph and policy checks matter: adding a bypass creates a real model path,
and removing a policy guard admits a packet with no encryption-policy evidence.
These are counterexamples inside the model, not faults injected into node-1.
-/
open TDN.MSC

example : Walk (("I_A1", "I_A2") :: grayEdges) "I_A1" "I_A2" := by
  exact .step (by simp) (.refl "I_A2")

def unguardedTable : ForwardTable :=
  { device := "I_A1", defaultAccept := false, rules := [{}] }

example : unguardedTable.accepts outerFirewallExample = true := by decide

example : forwardDecision "unknown-device" outerFirewallExample = none := by decide

example : Prefix.contains ⟨167837952, 24⟩ 167838207 = true := by decide
example : Prefix.contains ⟨167837952, 24⟩ 167838208 = false := by decide

example : deliver healthy healthy sameLevelPacket = some sameLevelPacket := by decide
example : deliver healthy healthy crossLevelPacket = none := by decide
example : deliver healthy { healthy with outerSA := false } sameLevelPacket = none := by decide
example : transmit { healthy with innerPolicy := false } sameLevelPacket = none := by decide
example : transmit { healthy with outerFirewallReady := false } sameLevelPacket = none := by decide

/- Print dependency audits for the main proof families. `sorryAx` or a newly
introduced project axiom would be visible here; the project uses neither. -/
#print axioms no_cross_level_gray_bypass
#print axioms encryptor_without_policy_drops
#print axioms cross_level_not_delivered
#print axioms ready_authorized_delivers
#print axioms sampled_retained_devices_running

/- The new contract proofs quantify over packet fields. The following concrete
cases additionally demonstrate why policy ID, direction, peer and protocol
constraints matter. These records do not modify the deployed network. -/
def innerOutgoing : RoutedPacket :=
  { input := "red", output := "gray", source := 167837954,
    destination := 167903490, protocol := 1, outPolicy := some 101 }

example : forwardDecision "I_A1" innerOutgoing = some true := by decide
example : forwardDecision "I_A1" { innerOutgoing with outPolicy := some 999 } = some false := by decide
example : forwardDecision "I_A1" { innerOutgoing with outPolicy := none, inPolicy := some 101 } = some false := by decide

example : Walk (("O_A1", "BLACK") :: withoutOuterFirewalls) "O_A1" "BLACK" := by
  exact .step (by simp) (.refl "BLACK")

example : ¬ (∀ e ∈ (("O_A1", "BLACK") :: withoutOuterFirewalls),
    blackRegion e.1 = blackRegion e.2) := by decide

example : ipv4? "10.1.1.2" = some 167837954 := by decide
example : ipv4? "256.1.1.2" = none := by decide
example : Prefix.parse? "10.1.1.0/33" = none := by decide

#print axioms declared_contract_accepts_iff
#print axioms accepted_outbound_requires_declared_policy
#print axioms no_outer_firewall_bypass
#print axioms intended_ike_lifetime_bound

/- The receiver guards are tested one at a time against a healthy sender. -/
example : TDN.MSC.deliver TDN.MSC.healthy
    { TDN.MSC.healthy with transportReady := false } TDN.MSC.sameLevelPacket = none := by decide

example : TDN.MSC.deliver TDN.MSC.healthy
    { TDN.MSC.healthy with outerFirewallReady := false } TDN.MSC.sameLevelPacket = none := by decide

example : TDN.MSC.deliver TDN.MSC.healthy
    { TDN.MSC.healthy with grayPathReady := false } TDN.MSC.sameLevelPacket = none := by decide

example : TDN.MSC.deliver TDN.MSC.healthy TDN.MSC.healthy TDN.MSC.sameLevelPacket =
    some TDN.MSC.sameLevelPacket := by decide
