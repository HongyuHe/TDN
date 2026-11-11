import TDN.Requirements.SnapshotCoversAllDeployedIfaces
import TDN.Models.MacsecExternalOutputProtection

namespace TDN.Requirements.StandardDataPlaneBridge
open Compliance LayeredFrame PacketSource MultiProtocolForwarding

theorem macsec_model_covers_deployment {S A : Type}
    (prototype : DeviceExecutionBinding S A) (ifaces : List Nat) (d : Deployment)
    (static : DeviceDeploymentBindings prototype ifaces d)
    (ifaceChecks : IfaceConditions prototype.configuration ifaces)
    (wireChecks : MACsecWireChecks prototype.configuration)
    (processing : HeaderProcessing) (mode : prototype.configuration.headerProcessing = some processing)
    (bounds : HeaderBounds processing)
    (sourceSafe : ∀ state, (model prototype ifaces d {}).initial state →
      MACsecOutputProtected prototype.configuration state.native ∧
        PhysicalMACsecFrames prototype.configuration state.native)
    (encoding : ∀ state, PhysicalMACsecFrames prototype.configuration state →
      prototype.configuration.LinkEncodingComplete state)
    (mtu : Nat → Nat) (sources : prototype.sourceProcessing = sourceProcessing mtu)
    (minimum : ∀ iface, 1280 ≤ mtu iface) (noUDPBindings : d.udpBindings = [])
    (sourceIfaces : ∀ request, (binding prototype ifaces).SourceRequestAllowed d request → request.iface ∈ ifaces)
    (networkSources : ∀ network ∈ d.networks, ∃ request datagrams,
      (binding prototype ifaces).SourceRequestAllowed d request ∧ request.application ≠ [] ∧
      prototype.origin request.originDomain = .red network.id ∧
      prototype.sourceProcessing.process request = .emitted datagrams) :
    (model prototype ifaces d {}).CoversDeployment d := by
  refine ⟨static.processing, standard_model_faithful prototype ifaces d {},
    standard_model_covers_every_native_step prototype ifaces d {} ifaceChecks,
    standard_generated_source_coverage prototype ifaces d {} mtu sources minimum noUDPBindings
      sourceIfaces networkSources,
    by simp [model, ObservedHistory.Valid],
    static.interfaceLinks, static.linkPolicies, static.headerGeneration, ?_,
    static.macsecKeys, static.ipsecKeys, static.redNetworks, static.peers,
    static.deviceIDs, static.interfaceIDs, static.tunnelIDs, static.interfaceIndices, ?_,
    static.physicalLinks, static.sourceEntries, static.macsecTunnels, static.ipsecTunnels⟩
  · intro start actions state initialized run
    have preserved : (model prototype ifaces d {}).system.TrInv (fun state =>
        MACsecOutputProtected prototype.configuration state.native ∧
          PhysicalMACsecFrames prototype.configuration state.native) := by
      intro before action after step invariant
      exact ⟨step_preserves_macsec_output_protection wireChecks.output step.2.2.2.1 invariant.1,
        step_preserves_physical_macsec_frames wireChecks step.2.2.2.1 invariant.1 invariant.2⟩
    have framed := (Cslib.LTS.mtrInv_of_trInv preserved start actions state run
      (sourceSafe start initialized)).2
    exact ⟨standard_reachable_headers prototype ifaces d {} processing mode bounds
      start state actions initialized run, encoding state.native framed⟩
  · intro state
    exact static.ifaceRecords state.native.iface state.ifacePresent

end TDN.Requirements.StandardDataPlaneBridge
