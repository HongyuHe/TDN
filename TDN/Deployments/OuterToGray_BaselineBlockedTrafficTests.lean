import TDN.Import.NativeDecide
import TDN.Deployments.OuterToGray_BaselineCases
import TDN.Deployments.OuterToGray_Counterexamples

namespace TDN.Deployments.OuterToGray_Baseline
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel MultiProtocolForwarding

set_option maxRecDepth 1000000
set_option maxHeartbeats 0
set_option synthInstance.maxSize 2048

load_network_records plaintextBlack : ForwardCase from "../../data/evidence/continuation/OuterToGray_BaselineCases.json" ["plaintextBlack"]

load_network_records inboundPolicy : DataPlaneForwarding.IpsecPolicy from "../../data/evidence/continuation/OuterToGray_BaselineCases.json" ["inboundPolicy"]

load_network_records inboundAssociation : DataPlaneForwarding.InstalledSA from "../../data/evidence/continuation/OuterToGray_BaselineCases.json" ["inboundAssociation"]

load_network_records loopbackIface : Nat from "../../data/evidence/continuation/OuterToGray_BaselineCases.json" ["loopbackIface"]

load_network_records erspanIface : Nat from "../../data/evidence/continuation/OuterToGray_BaselineCases.json" ["erspanIface"]

lemma plaintext_Black_context_remains_supported (base : Deployment) :
    (records.deployment base).SupportedAt plaintextBlack.interface .outbound (plaintextBlack.context records)
      ((records.deployment base).Observe (plaintextBlack.packet records)) :=
  checked_plain_forward_case_is_supported plaintextBlack records base .outbound (by unfold_check_parameters; native_decide)

lemma plaintext_Black_is_required_to_decrypt (base : Deployment) :
    (records.deployment base).InboundIPsecRequired records.inventory plaintextBlack.entryIface
      (plaintextBlack.context records).header := by
  unfold_check_parameters; native_decide

lemma plaintext_Black_context_fails_positive_prerequisite (base : Deployment) :
    ¬ (records.deployment base).ContextIngressEligible (plaintextBlack.context records)
      ((records.deployment base).Observe (plaintextBlack.packet records)) :=
  checked_plaintext_required_arrival_is_not_positive_eligible plaintextBlack records base
    (plaintext_Black_is_required_to_decrypt base)

lemma plaintext_Black_is_denied_by_raw_Gray_forward_program :
    Filter.evaluate ((records.configuration.ip.forwardRules plaintextBlack.route.egress).map PacketPolicy.Rule.toFilter)
      (records.configuration.ip.forwardFallback plaintextBlack.route.egress)
      (plaintextBlack.packet records) = .deny := by
  native_decide

def authenticatedReturn : PacketPolicy.Packet :=
  { plaintextBlack.packet records with matchedInboundPolicyIds := [inboundPolicy.id] }

lemma authenticated_return_is_allowed_by_raw_program :
    DataPlaneForwarding.accepts (records.configuration.ip.forwardRules plaintextBlack.route.egress)
      (records.configuration.ip.forwardFallback plaintextBlack.route.egress) authenticatedReturn := by
  native_decide

lemma authenticated_return_is_not_Gray_inbound_at_any_native_iface :
    ∀ iface ∈ records.inventory.ifaces, records.ifaceName iface = plaintextBlack.interface.id →
      ¬ PacketAtHook (records.configuration.ip.interfaceName iface) .inbound .forward authenticatedReturn := by
  unfold PacketAtHook HookDirection
  native_decide

lemma authenticated_return_cannot_be_misattributed_to_Gray_inbound (base : Deployment) :
    ¬ (records.deployment base).HookContext plaintextBlack.interface.id .inbound .forward authenticatedReturn := by
  rintro ⟨inventory, present, iface, member, name, interface, interfaceMember, interfaceName, owner, atHook⟩
  have same : inventory = records.inventory := Option.some.inj present.symm
  subst inventory
  exact authenticated_return_is_not_Gray_inbound_at_any_native_iface iface member name atHook

def encryptedHeader : PacketPolicy.Packet :=
  { LayeredFrame.outerHeader inboundPolicy.sender inboundPolicy.receiver "esp" 0 0 with hopLimit := 64 }

def encryptedEntry (iface : Nat) : MultiProtocolForwarding.State :=
  { plaintextBlack.entry with
    iface := iface
    enteredIface := iface
    frame := plaintextBlack.entry.frame.pushHeader
      (.ipsec (inboundPolicy.seal inboundAssociation) plaintextBlack.entry.frame.body) (some encryptedHeader) }

def decryptedEntry (iface : Nat) : MultiProtocolForwarding.State :=
  { encryptedEntry iface with
    initialEntry := false
    datapathStage := .ingress
    enteredIface := iface
    frame := records.configuration.restoredFrame (encryptedEntry iface).frame plaintextBlack.entry.frame.body
    authenticated := [inboundPolicy.id]
    tracking := "new" }

def decryptedRoute (iface : Nat) : DataPlaneForwarding.FibRoute :=
  { plaintextBlack.route with ingress := iface }

def decryptedRouted (iface : Nat) : MultiProtocolForwarding.State :=
  { decryptedEntry iface with
    initialEntry := false
    iface := plaintextBlack.route.egress
    datapathStage := .routed
    frame := records.configuration.forwardedFrame (decryptedEntry iface).frame }

def decryptedContext (iface : Nat) : PacketProcessing.Context :=
  { plaintextBlack.context records with entry := encryptedEntry iface, state := decryptedRouted iface }

lemma encrypted_entry_headers_are_coherent (iface : Nat) :
    (encryptedEntry iface).frame.HeadersCoherent := by
  refine ⟨⟨rfl, by change 64 ≤ 255; native_decide⟩, none, [], rfl, ?_⟩
  exact ⟨⟨rfl, by change 64 ≤ 255; native_decide⟩, rfl⟩

lemma configured_outer_decryption (iface : Nat)
    (configured : inboundPolicy ∈ records.configuration.ip.ingressPolicies iface)
    (installed : inboundAssociation ∈ records.configuration.ip.ingressSAs iface) :
    MultiProtocolForwarding.Step records.configuration (encryptedEntry iface) .decryptIPsec (decryptedEntry iface) :=
  .decryptIPsec inboundPolicy inboundAssociation plaintextBlack.entry.frame.body plaintextBlack.header
    rfl rfl configured installed (by native_decide) rfl (by native_decide) "new"

lemma loopback_admits_encrypted_envelope_at_INPUT :
    PacketProcessing.InputAdmitted records.configuration (encryptedEntry loopbackIface) := by
  refine ⟨encryptedHeader, rfl, ?_⟩
  native_decide

lemma Black_admits_encrypted_envelope_at_INPUT :
    PacketProcessing.InputAdmitted records.configuration (encryptedEntry plaintextBlack.entryIface) := by
  refine ⟨encryptedHeader, rfl, ?_⟩
  native_decide

lemma erspan_rejects_encrypted_envelope_at_INPUT :
    ¬ PacketProcessing.InputAdmitted records.configuration (encryptedEntry erspanIface) := by
  rintro ⟨header, visible, admitted⟩
  have same : header = encryptedHeader := Option.some.inj visible.symm
  subst header
  exact (by native_decide :
    ¬ DataPlaneForwarding.accepts (records.configuration.ip.inputRules erspanIface)
      (records.configuration.ip.inputFallback erspanIface)
      (PacketProcessing.inputPacket records.configuration (encryptedEntry erspanIface) encryptedHeader)) admitted

lemma loopback_remote_envelope_has_no_native_arrival (base : Deployment) :
    ¬ (records.deployment base).DeviceArrivalEligible records.inventory (encryptedEntry loopbackIface) := by
  rw [device_arrival_iff_visible_source _ _ _ encryptedHeader rfl]
  unfold Deployment.LocalSourceAddress
  unfold_check_parameters; native_decide

lemma erspan_remote_envelope_has_no_native_arrival (base : Deployment) :
    ¬ (records.deployment base).DeviceArrivalEligible records.inventory (encryptedEntry erspanIface) := by
  rw [device_arrival_iff_visible_source _ _ _ encryptedHeader rfl]
  unfold Deployment.LocalSourceAddress
  unfold_check_parameters; native_decide

lemma Black_envelope_has_native_arrival (base : Deployment) :
    (records.deployment base).DeviceArrivalEligible records.inventory (encryptedEntry plaintextBlack.entryIface) := by
  apply Or.inl
  native_decide

lemma invented_loopback_decryption_and_route :
    MultiProtocolForwarding.Step records.configuration (encryptedEntry loopbackIface) .decryptIPsec (decryptedEntry loopbackIface) ∧
      MultiProtocolForwarding.Step records.configuration (decryptedEntry loopbackIface) .route (decryptedRouted loopbackIface) := by
  refine ⟨configured_outer_decryption loopbackIface (by native_decide)
    (by native_decide), ?_⟩
  exact .route (decryptedRoute loopbackIface) rfl rfl (by native_decide) rfl

lemma actual_Black_decryption_and_route :
    MultiProtocolForwarding.Step records.configuration (encryptedEntry plaintextBlack.entryIface) .decryptIPsec
        (decryptedEntry plaintextBlack.entryIface) ∧
      MultiProtocolForwarding.Step records.configuration (decryptedEntry plaintextBlack.entryIface) .route
        (decryptedRouted plaintextBlack.entryIface) := by
  refine ⟨configured_outer_decryption plaintextBlack.entryIface (by native_decide)
    (by native_decide), ?_⟩
  exact .route (decryptedRoute plaintextBlack.entryIface) rfl rfl (by native_decide) rfl

lemma actual_Black_context_satisfies_ingress_prerequisites (base : Deployment) :
    (records.deployment base).ContextIngressEligible (decryptedContext plaintextBlack.entryIface)
      ((records.deployment base).Observe ((decryptedContext plaintextBlack.entryIface).Packet records.configuration)) := by
  refine ⟨records.inventory, rfl, encrypted_entry_headers_are_coherent _, fun _ =>
    Black_envelope_has_native_arrival base, ?_⟩
  intro _ _
  exact Or.inl ⟨decryptedEntry plaintextBlack.entryIface, actual_Black_decryption_and_route.1,
    actual_Black_decryption_and_route.2, Black_admits_encrypted_envelope_at_INPUT⟩


def inconsistentHeaderEntry : MultiProtocolForwarding.State :=
  { plaintextBlack.entry with frame := { plaintextBlack.entry.frame with
      activeHeader := some { plaintextBlack.header with source := plaintextBlack.header.source + 1 } } }

lemma inconsistent_active_header_is_not_coherent :
    ¬ inconsistentHeaderEntry.frame.HeadersCoherent := by
  rintro ⟨⟨identity, _⟩, _⟩
  have source := congrArg PacketPolicy.Packet.source identity
  exact Nat.succ_ne_self plaintextBlack.header.source source

end TDN.Deployments.OuterToGray_Baseline
