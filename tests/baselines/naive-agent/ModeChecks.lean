import TDN.Import.SnapshotLoader
import TDN.Requirements.MscRequirements

open TDN TDN.Compliance TDN.Requirements TDN.Requirements.Msc

set_option Elab.async false

namespace TDN.Benchmark

def ConfiguredTunnelModes (rows : List (String × String)) : Prop :=
  ∀ row ∈ rows, row.2 = "TUNNEL"

instance (rows : List (String × String)) : Decidable (ConfiguredTunnelModes rows) := by
  unfold ConfiguredTunnelModes
  infer_instance

def ModeObservationsMatch (rows : List (String × String)) (components : List EncryptionComponentConfiguration) : Prop :=
  ∀ row ∈ rows, ∃ component ∈ components, component.id = row.1 ∧ component.protocol = .ipsec ∧
    (component.espTunnelMode = true ↔ row.2 = "TUNNEL")

theorem rg029_requires_observed_tunnel_modes {S A : Type} {net : Deployment}
    {model : ForwardingModel S A} {components : List EncryptionComponentConfiguration} {outbound inbound : Bool}
    {rows : List (String × String)} (claim : inner_tunnel_no_bypass net model components outbound inbound)
    (recorded : ModeObservationsMatch rows components) : ConfiguredTunnelModes rows := by
  intro row member
  obtain ⟨component, listed, _, ipsec, mode⟩ := recorded row member
  exact mode.mp (((claim.2.2 component listed (Or.inl rfl)).1 ipsec).1)

theorem rg030_requires_observed_tunnel_modes {S A : Type} {net : Deployment}
    {model : ForwardingModel S A} {components : List EncryptionComponentConfiguration} {outbound inbound : Bool}
    {rows : List (String × String)} (claim : outer_tunnel_no_bypass net model components outbound inbound)
    (recorded : ModeObservationsMatch rows components) : ConfiguredTunnelModes rows := by
  intro row member
  obtain ⟨component, listed, _, ipsec, mode⟩ := recorded row member
  exact mode.mp ((claim.2.2.1 component listed (Or.inl rfl)).1 ipsec)

load_network_records innerModes : List (String × String) from "evidence.json" ["inner"]
load_network_records outerModes : List (String × String) from "evidence.json" ["outer"]

run_cmd do Lean.logInfo m!"TDN_BEGIN {← IO.monoNanosNow}"

example : ConfiguredTunnelModes innerModes := by native_decide
example : ConfiguredTunnelModes outerModes := by native_decide

run_cmd do Lean.logInfo m!"TDN_END {← IO.monoNanosNow}"

end TDN.Benchmark
