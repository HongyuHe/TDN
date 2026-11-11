import TDN.Deployments.InnerTunnelNoBypass_IPsec
import TDN.Deployments.MtuSizing_DownstreamPath

namespace TDN.Deployments.InnerTunnelNoBypass_IPsec
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel MtuSizing_Records StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

structure DeliveryMove where
  step : SizingMove
  domain : Nat
  source : IPsecLocalSA
  receiver : IPsecLocalSA

def DeliveryMove.after (move : DeliveryMove) (before : MultiProtocolForwarding.State) : MultiProtocolForwarding.State :=
  match move.step.operation with
  | .decryptIPsec => match before.frame.body with
      | .ipsec _ body => { before with
          initialEntry := false, datapathStage := .ingress,
          enteredIface := before.iface, frame := (records.configuration.restoredFrame before.frame body),
          authenticated := [move.step.policy.id], tracking := "new" }
      | _ => before
  | .inputFilter => { before with initialEntry := false, datapathStage := .localInput }
  | .deliver => { before with initialEntry := false, datapathStage := .delivered }
  | _ => move.step.after records before

def DeliveryMove.Check (move : DeliveryMove) (before : MultiProtocolForwarding.State) : Prop :=
  match move.step.operation with
  | .decryptIPsec => match before.frame.body with
      | .ipsec actual body => before.datapathStage = .received ∧
          actual = move.step.policy.seal move.step.association ∧
          move.step.policy ∈ capturedConfiguration.ip.ingressPolicies before.iface ∧
          move.step.association ∈ capturedConfiguration.ip.ingressSAs before.iface ∧
          DataPlaneForwarding.saMatchesPolicy move.step.association move.step.policy ∧
          body.visibleHeader = some move.step.header ∧ move.step.policy.matches move.step.header = true
      | _ => False
  | .inputFilter => before.datapathStage = .ingress ∧
      records.configuration.visibleHeader before.frame = some move.step.header ∧
      records.configuration.ip.localAddress before.iface move.step.header.destination ∧
      DataPlaneForwarding.accepts (records.configuration.ip.inputRules before.iface)
        (records.configuration.ip.inputFallback before.iface)
        (policyHeader { records.configuration with networkBytes := fun body _ => IPsecFrameEncoding.networkLength body }
          before move.step.header)
  | .deliver => before.datapathStage = .localInput ∧ before.frame.body = .datagram move.step.header ∧
      records.configuration.ip.ifaceSecurityDomain before.iface = some move.domain
  | _ => move.step.Check records installations before

instance deliveryMoveCheckDecidable (move : DeliveryMove) (before : MultiProtocolForwarding.State) : Decidable (move.Check before) := by
  unfold DeliveryMove.Check DataPlaneForwarding.accepts
  cases move.step.operation <;> dsimp only <;> try infer_instance
  all_goals try { cases before.frame.body <;> dsimp only <;> infer_instance }
  all_goals dsimp [Records.configuration]; infer_instance

def DeliveryMove.Keys (move : DeliveryMove) (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial)
    (before : MultiProtocolForwarding.State) : Prop :=
  move.step.operation = .decryptIPsec →
    move.source ∈ (deviceBinding primitive).ipsecInstallations ∧ move.receiver ∈ (deviceBinding primitive).ipsecInstallations ∧
    ∃ stamp body, before.frame.body = .ipsec stamp body ∧ (move.after before).frame.body = body ∧
      move.source.OutboundSeal (deviceBinding primitive) stamp ∧ move.receiver.InboundSeal (deviceBinding primitive) before.iface stamp ∧
      IPsecKeyMaterialMatches (deviceBinding primitive).ipsecKeyMaterial move.source move.receiver

lemma DeliveryMove.device_step (move : DeliveryMove) (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial)
    (before : MultiProtocolForwarding.State) (checked : move.Check before) :
    MultiProtocolForwarding.Step (configuration primitive) before move.step.operation (move.after before) := by
  by_cases decryption : move.step.operation = .decryptIPsec
  · cases shape : before.frame.body <;> simp only [DeliveryMove.Check, decryption, shape] at checked
    next association body =>
      obtain ⟨stage, same, configured, installed, bound, visible, selector⟩ := checked
      have encrypted : before.frame.body = .ipsec (move.step.policy.seal move.step.association) body := shape.trans (congrArg (fun stamp => Body.ipsec stamp body) same)
      simpa [DeliveryMove.after, decryption, shape, Config.restoredFrame, configuration,
        completeConfiguration, directionalConfiguration, Records.configuration] using
        (MultiProtocolForwarding.Step.decryptIPsec (c := configuration primitive) move.step.policy move.step.association
          body move.step.header stage encrypted configured installed bound visible selector "new")
  · by_cases input : move.step.operation = .inputFilter
    · simp only [DeliveryMove.Check, input] at checked
      obtain ⟨stage, visible, localAddress, accepted⟩ := checked
      simpa only [DeliveryMove.after, input] using
        (MultiProtocolForwarding.Step.inputFilter (c := configuration primitive) stage visible localAddress accepted)
    · by_cases delivery : move.step.operation = .deliver
      · simp only [DeliveryMove.Check, delivery] at checked
        obtain ⟨stage, plain, domain⟩ := checked
        simpa only [DeliveryMove.after, delivery] using
          (MultiProtocolForwarding.Step.deliver (c := configuration primitive) move.domain stage plain domain)
      · have ordinary : move.step.Check records installations before := by
          simpa only [DeliveryMove.Check, decryption, input, delivery] using checked
        have same : move.after before = move.step.after records before := by
          cases operation : move.step.operation <;> simp_all [DeliveryMove.after]
        rw [same]
        exact move.step.step records installations linkPolicies (codec primitive) before ordinary

lemma DeliveryMove.accepted (move : DeliveryMove) (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial)
    (before : MultiProtocolForwarding.State) (checked : move.Check before)
    (keys : move.Keys primitive before) (links : move.step.LinkCheck records linkPolicies before)
    (description : (IPsecFrameEncoding.linkEncoding (codec primitive) before.frame).Describes before.frame) :
    (interpretedForwarding primitive).native.AcceptedStep before move.step.operation (move.after before) := by
  by_cases decryption : move.step.operation = .decryptIPsec
  · refine ⟨move.device_step primitive before checked, ?_, ?_, ?_, ?_, ?_⟩
    · simp [decryption]
    · intro _
      obtain ⟨source, receiver, stamp, body, original, restored, outbound, inbound, matching⟩ := (show move.step.operation = .decryptIPsec → _ from keys) decryption
      exact ⟨move.source, source, move.receiver, receiver, stamp, body, original, restored, outbound, inbound, matching⟩
    · simp [Config.LinkStepAdmitted, decryption]
    · simp [Config.HeaderStepAdmitted, decryption]
    · simp [decryption]
  · by_cases input : move.step.operation = .inputFilter
    · refine ⟨move.device_step primitive before checked, ?_, ?_, ?_, ?_, ?_⟩
      all_goals simp [Config.LinkStepAdmitted, Config.HeaderStepAdmitted, input]
    · by_cases delivery : move.step.operation = .deliver
      · have plain : before.frame.body = .datagram move.step.header := by
          have deliveryCheck := checked
          simp only [DeliveryMove.Check, delivery] at deliveryCheck
          exact deliveryCheck.2.1
        refine ⟨move.device_step primitive before checked, ?_, ?_, ?_, ?_, ?_⟩
        · simp [delivery]
        · simp [delivery]
        · simp [Config.LinkStepAdmitted, delivery, Frame.visibleHeader, plain, Body.visibleHeader]
        · simp [Config.HeaderStepAdmitted, delivery]
        · simp [delivery]
      · have ordinary : move.step.Check records installations before := by
          simpa only [DeliveryMove.Check, decryption, input, delivery] using checked
        have same : move.after before = move.step.after records before := by
          cases operation : move.step.operation <;> simp_all [DeliveryMove.after]
        rw [same]
        exact move.step.accepted records installations entries roles linkPolicies epoch (codec primitive) material before ordinary links description

end TDN.Deployments.InnerTunnelNoBypass_IPsec
