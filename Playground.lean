import TDN

open TDN.MSC

-- Move the cursor into a proof to see its goal in the Lean Infoview.
-- Change the payload or host endpoints below and inspect the evaluation result.
#eval transmit healthy sameLevelPacket
#eval transmit healthy crossLevelPacket

-- `decide` proves concrete, decidable propositions by computation.
example : transmit healthy crossLevelPacket = none := by
  decide

-- `exact` reuses an existing theorem with its explicit assumptions.
example (state : GatewayState) (packet : Packet)
    (different : packet.source.level ≠ packet.destination.level) :
    transmit state packet = none := by
  exact cross_level_blocked state packet different

-- `simp` unfolds the model and simplifies the failed authentication check.
example (state : GatewayState) (packet : Packet)
    (untrusted : state.innerPeerAuthenticated = false) :
    transmit state packet = none := by
  simp [transmit, innerEncrypt, untrusted]

-- Try proving the outer-peer version above by cases on `innerEncrypt`.
-- The proof of `outer_failure_closed` in TDN/MSC/Flow.lean has the same shape.

-- The imported topology supports an unbounded graph theorem, not only a probe.
-- `Walk` permits arbitrarily long walks, including repeated vertices.
#check no_cross_level_gray_bypass
example : ¬ Walk grayEdges "I_A1" "I_A2" := by
  exact site_a_gray_cut

-- Firewall evaluation uses the observed FORWARD rules from the pinned export.
-- `some false` means a known rejection; `none` means a missing device table.
#eval forwardDecision "OF_A1" outerFirewallExample
#eval forwardDecision "OF_A1" { outerFirewallExample with protocol := 1 }
#eval forwardDecision "unknown-device" outerFirewallExample

-- The following proof quantifies over every modeled packet. A missing policy
-- tag is different from a missing observation about whether a tag exists.
example (table : ForwardTable) (member : table ∈ encryptorTables)
    (packet : RoutedPacket) (hin : packet.inPolicy = none)
    (hout : packet.outPolicy = none) : table.accepts packet = false := by
  exact encryptor_without_policy_drops table member packet hin hout
