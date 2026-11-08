import TDN.Targets.CanonicalDeploymentCoverage
import TDN.Targets.CompleteSpecifications

namespace TDN.Targets.Complete
open Compliance CanonicalExecution LayeredFrame PacketSource MultiProtocolExecution IPsecFrameEncoding


def InterfaceSizingFamily (interface : Interface) (setting : PacketSizing) : Prop :=
  match interface.address with
  | none => True
  | some address => (address < 2^32 → setting.family = .ipv4) ∧
      (2^128 ≤ address → setting.family = .ipv6)

instance (interface : Interface) (setting : PacketSizing) : Decidable (InterfaceSizingFamily interface setting) := by
  unfold InterfaceSizingFamily
  split <;> infer_instance


def SizingInventoryChecks (d : Deployment) (ifaceName : Nat → String) (settings : List PacketSizing) : Prop :=
  (∀ device ∈ d.devices, device.kind = .grayFirewall →
    ∃ interface ∈ d.interfaces, interface.device = device.id ∧ interface.externalData = true) ∧
  ∀ interface ∈ d.interfaces, ∀ device ∈ d.devices, interface.device = device.id →
    ((device.layer = some .inner ∧ interface.zone = .gray) ∨
      (device.layer = some .outer ∧ interface.zone = .black) ∨
      (device.kind = .grayFirewall ∧ interface.externalData = true)) →
    ∃ setting ∈ settings, ifaceName setting.interface = interface.id ∧
      setting.role = (if device.layer = some .inner then .innerExternal else .grayFirewallOrEncryptionExternal) ∧
      InterfaceSizingFamily interface setting

instance (d : Deployment) (ifaceName : Nat → String) (settings : List PacketSizing) :
    Decidable (SizingInventoryChecks d ifaceName settings) := by
  unfold SizingInventoryChecks
  infer_instance


theorem sizing_inventory_from_records {S A : Type} (d : Deployment) (model : ExecutionModel S A)
    (settings : List PacketSizing) (checks : SizingInventoryChecks d model.native.ifaceName settings) :
    PacketSizingInventory d model settings := by
  refine ⟨fun device member relevant role => checks.1 device member role, ?_⟩
  intro interface member device deviceMember owner relevant role
  obtain ⟨setting, settingMember, name, kind, family⟩ := checks.2 interface member device deviceMember owner role
  refine ⟨setting, settingMember, name, kind, ?_⟩
  intro address assigned
  rw [InterfaceSizingFamily, assigned] at family
  exact family


theorem complete_canonical_IPsec_packet_sizing {S A Key : Type}
    (prototype : NativeExecutionBinding S A) (ifaces : List Nat) (d : Deployment) (history : ObservedHistory)
    (static : NativeDeploymentBindings prototype ifaces { d with focus := none }) (historyValid : history.Valid)
    (ifaceChecks : IfaceConditions prototype.configuration ifaces)
    (codec : Codec Key) (required : Nat → Bool) (mtu payloadLimit plaintextLimit authenticationLimit : Nat → Nat)
    (sizeChecks : SizeChecks prototype.configuration required mtu plaintextLimit authenticationLimit)
    (links : EthernetMTUChecks prototype.configuration mtu)
    (processing : HeaderProcessing) (mode : prototype.configuration.headerProcessing = some processing)
    (headerBounds : HeaderBounds processing)
    (encoding : ∀ iface frame, prototype.configuration.linkEncoding iface frame = some (linkEncoding codec frame))
    (sources : prototype.sourceProcessing = sourceProcessing mtu) (minimum : ∀ iface, 1280 ≤ mtu iface)
    (noUDPBindings : d.udpBindings = [])
    (sourceIfaces : ∀ request, (binding prototype ifaces).SourceRequestAllowed { d with focus := none } request → request.iface ∈ ifaces)
    (networkSources : ∀ network ∈ d.networks, ∃ request datagrams,
      (binding prototype ifaces).SourceRequestAllowed { d with focus := none } request ∧ request.application ≠ [] ∧
      prototype.origin request.originDomain = .red network.id ∧ prototype.sourceProcessing.process request = .emitted datagrams)
    (settings : List PacketSizing)
    (settingsMatch : SettingsUseInterfaceCeilings settings required mtu payloadLimit)
    (settingsScope : ∀ setting ∈ settings, setting.family = .ipv4 ∧ setting.innerObjectiveSelected = false)
    (inventory : SizingInventoryChecks { d with focus := none } prototype.ifaceName settings) :
    msc_packet_size_configuration d (model prototype ifaces { d with focus := none } history)
      (sizedWireModel codec mtu payloadLimit) settings [] := by
  have emissions : EmissionConditions prototype.sourceProcessing := by
    rw [sources]
    exact source_processing_emission_conditions mtu minimum
  have sourceMtu : prototype.sourceProcessing.sourceMtu = mtu := by rw [sources]; rfl
  have behavior := canonical_packet_size_correspondence prototype ifaces { d with focus := none } history codec
    required mtu payloadLimit plaintextLimit authenticationLimit sizeChecks links emissions sourceMtu minimum
    processing mode headerBounds settings settingsMatch
  refine ⟨canonical_deployment_covered prototype ifaces { d with focus := none } history static historyValid ifaceChecks
      codec required mtu plaintextLimit authenticationLimit sizeChecks processing mode headerBounds encoding sources
      minimum noUDPBindings sourceIfaces networkSources,
    behavior.1, behavior.2, sizing_inventory_from_records _ _ settings inventory, ?_⟩
  intro setting member
  have facts := settingsMatch setting member
  have scope := settingsScope setting member
  refine ⟨?_, ?_⟩
  · intro role
    refine ⟨?_, ?_, ?_, ?_⟩
    · rw [facts.2.1]
      exact lt_of_lt_of_le (by decide : 0 < 1280) (minimum _)
    · exact lt_of_lt_of_le (lt_of_lt_of_le (by decide : 0 < 1280) (minimum _)) facts.2.2.2.1
    · rw [scope.1]
      intro impossible
      cases impossible
    · intro bytes bound
      rw [facts.2.2.2.2, facts.2.1]
  · intro role selected
    rw [scope.2] at selected
    contradiction

end TDN.Targets.Complete
