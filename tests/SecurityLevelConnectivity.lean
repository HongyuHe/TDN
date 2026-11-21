import TDN.Deployments.SecurityLevelConnectivity_Baseline
import TDN.Deployments.SecurityLevelConnectivity_Shared

namespace TDN.Tests.SecurityLevelConnectivity
open Compliance Requirements Requirements.Msc StandardDataPlaneBridge
open Deployments.SecurityLevelConnectivity_Shared Deployments.OuterTunnelNoBypass_Shared Deployments.MtuSizing_Records

private lemma a2_cannot_deliver_to_b3 (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial) :
    (interpretedForwarding primitive).AllTraces (fun events => ∀ payload layers,
      ¬ Before events (.inject payload "V31F_I_A2/red-network") (.deliver payload "V31F_I_B3/red-network" layers)) := by
  have labels : ∀ a ∈ redNetworks, ∀ b ∈ redNetworks,
      a.id = "V31F_I_A2/red-network" → b.id = "V31F_I_B3/red-network" →
      a.level.classification = b.level.classification ∧ a.level.dissemination ≠ b.level.dissemination := by native_decide
  have safe := (snapshot_rg008_shared_scoped_connectivity primitive).2.2.2.2.1
  intro start actions finish initial run payload layers order
  obtain ⟨a, listedA, b, listedB, source, destination, same⟩ :=
    safe start actions finish initial run payload _ _ layers order
  exact (labels a listedA b listedB source destination).2 (congrArg SecurityLevel.dissemination same)

example (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial) :
    ∃ start actions finish payload,
      (interpretedForwarding primitive).initial start ∧ (interpretedForwarding primitive).ForwardsAlongTrace start actions finish ∧
      Before ((interpretedForwarding primitive).TraceEvents actions)
        (.inject payload "V31F_I_A4/red-network") (.deliver payload "V31F_I_B4/red-network" []) :=
  required_pairs_have_forwarding_traces primitive (_, _) (by native_decide)

example : unclassifiedNetworkIds redNetworks =
    ["V31F_I_A4/red-network", "V31F_I_B4/red-network"] := by native_decide

example (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial) :
    ¬ scoped_security_level_connectivity (labelDeployment primitive) (interpretedForwarding primitive)
      (("V31F_I_A2", "V31F_I_B3") :: authenticated) installed requiredPairs
      (unclassifiedNetworkIds redNetworks) := by
  intro wrong
  obtain ⟨first, listedF, last, listedL, firstId, lastId, _, _, levels⟩ :=
    wrong.2.2.2.1 ("V31F_I_A2", "V31F_I_B3") (by simp)
  have separated : ∀ a ∈ devices, ∀ b ∈ devices, a.id = "V31F_I_A2" →
      b.id = "V31F_I_B3" → a.level ≠ b.level := by native_decide
  exact separated first listedF last listedL firstId lastId levels

example (classification : String) (compartments dissemination controls : Finset String)
    (changed : Finset String) (different : compartments ≠ changed) :
    (⟨classification, compartments, dissemination, controls⟩ : SecurityLevel) ≠
      ⟨classification, changed, dissemination, controls⟩ :=
  fun same => different (congrArg SecurityLevel.compartments same)

example (classification : String) (compartments dissemination controls : Finset String)
    (changed : Finset String) (different : controls ≠ changed) :
    (⟨classification, compartments, dissemination, controls⟩ : SecurityLevel) ≠
      ⟨classification, compartments, dissemination, changed⟩ :=
  fun same => different (congrArg SecurityLevel.otherControls same)

private def a2ToB3Flow : SourceFlow :=
  { iface := 105, domain := 2, source := 0x0A01020A, destination := 0x0A02030A }

private def a2ToB3Request := a2ToB3Flow.request

private def a2ToB3Header : PacketPolicy.Packet :=
  a2ToB3Request.body.originalHeader.get (by decide)

private def a2ToB3Datagram :=
  (PacketSource.encodeSourceDatagram a2ToB3Request a2ToB3Header a2ToB3Request.application).asWhole

example :
    redNetwork a2ToB3Flow.domain = "V31F_I_A2/red-network" ∧
    (∃ source ∈ capture.endpoints, source.network = "V31F_I_A2/red-network" ∧ source.host = "V31F_R_A2") ∧
    (∃ destination ∈ capture.endpoints, destination.network = "V31F_I_B3/red-network" ∧ destination.host = "V31F_R_B3") ∧
    (∃ source ∈ records.interfaces, source.device = "V31F_R_A2" ∧ source.address = some a2ToB3Flow.source) ∧
    (∃ destination ∈ records.interfaces, destination.device = "V31F_R_B3" ∧
      destination.address = some a2ToB3Flow.destination) := by
  native_decide

example (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial) :
    let model := interpretedForwarding primitive
    ∃ start, model.initial start ∧ model.sourceRecord start = some (a2ToB3Request, a2ToB3Datagram) ∧
      ∀ actions finish, model.ForwardsAlongTrace start actions finish → ∀ payload layers,
        ¬ Before (model.TraceEvents actions) (.inject payload "V31F_I_A2/red-network")
          (.deliver payload "V31F_I_B3/red-network" layers) := by
  have allowed : (binding (deviceBinding primitive) records.inventory.ifaces).SourceRequestAllowed
      (interpretedDeployment primitive) a2ToB3Request := by
    refine ⟨Or.inl ⟨a2ToB3Header, rfl⟩, rfl, ?_⟩
    change sourceEntry entries 105 = some (redNetwork 2) ∧ ∃ network ∈ networks, network.id = redNetwork 2
    native_decide
  have emitted : (deviceBinding primitive).sourceProcessing.process a2ToB3Request = .emitted [a2ToB3Datagram] := by
    change PacketSource.processSource (sourceMtu roles 105) a2ToB3Request = _
    native_decide
  obtain ⟨_, start, initial, _, record⟩ := (interpreted_deployment_covered primitive).sources.2.1
    a2ToB3Request [a2ToB3Datagram] a2ToB3Datagram allowed emitted (by simp)
  exact ⟨start, initial, record, fun actions finish run =>
    a2_cannot_deliver_to_b3 primitive start actions finish initial run⟩

end TDN.Tests.SecurityLevelConnectivity
