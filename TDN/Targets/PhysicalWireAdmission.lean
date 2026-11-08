import TDN.Targets.PhysicalBoundaryCoverage

namespace TDN.Targets.Complete
open MultiProtocolExecution

lemma native_wire_is_admitted_by_recorded_directional_programs (configuration : Config)
    (before after : MultiProtocolExecution.State) (encoded : LinkAdmission.Frame)
    (wire : MultiProtocolExecution.Step configuration before .linkTransmit after)
    (beforeEncoding : configuration.linkEncoding before.iface before.frame = some encoded)
    (afterEncoding : configuration.linkEncoding after.iface after.frame = some encoded)
    (describes : encoded.Describes before.frame)
    (outbound : LinkAdmission.Admitted configuration.linkPolicies before.iface true
      (encoded.Packet "" (configuration.ip.interfaceName before.iface)))
    (inbound : LinkAdmission.Admitted configuration.linkPolicies after.iface false
      (encoded.Packet (configuration.ip.interfaceName after.iface) "")) :
    configuration.LinkStepAdmitted before .linkTransmit after := by
  have sameFrame : after.frame = before.frame := by cases wire; rfl
  refine ⟨?_, by simp, by simp, by simp⟩
  intro _
  refine ⟨fun _ => ⟨encoded, beforeEncoding, describes, outbound⟩,
    fun _ => ⟨encoded, afterEncoding, sameFrame ▸ describes, ?_⟩,
    fun _ => beforeEncoding.trans afterEncoding.symm⟩
  simpa using inbound

end TDN.Targets.Complete
