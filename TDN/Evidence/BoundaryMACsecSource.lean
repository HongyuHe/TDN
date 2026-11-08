import TDN.Evidence.BoundaryMACsecCases

namespace TDN.Imported.BoundaryMACsec
open Compliance Targets Targets.Complete MultiProtocolExecution LayeredFrame

def SourceChecks (records : Records) : Prop :=
  records.sourceCase.entryIface ∈ records.inventory.ifaces ∧
  (∃ peer ∈ records.inventory.ifaces,
    records.configuration.physicalLink peer records.sourceCase.entryIface) ∧
  IPFrameChecks records.sourceFrame records.sourceCase.header records.sourceNetwork
    records.sourceTransport records.sourceCase.application ∧
  IPFrameChecks records.logicalFrame records.sourceCase.forwardedHeader records.logicalNetwork
    records.logicalTransport records.sourceCase.application ∧
  records.sourceCase.header.payloadBytes = some records.sourceCase.application ∧
  records.sourceCase.forwardedHeader.payloadBytes = some records.sourceCase.application

instance (records : Records) : Decidable (SourceChecks records) := by
  unfold SourceChecks
  infer_instance

lemma captured_source_checks :
    ∀ records ∈ [protectedCase, unprotectedAllowed, unprotectedDenied], SourceChecks records := by
  exact of_decide_eq_true rfl

lemma checked_source_frames_bind_native_entry_and_logical_output (records : Records)
    (checks : SourceChecks records) :
    NativeIngressAttachment records.inventory records.sourceCase.entryIface ∧
    records.sourceFrame.Describes records.sourceCase.entry.frame ∧
    records.logicalFrame.Describes (records.sourceCase.ready records.configuration).frame := by
  obtain ⟨_, attachment, source, logical, application, forwardedApplication⟩ := checks
  refine ⟨Or.inl attachment, ?_, ?_⟩
  · exact checked_IP_frame_describes_native records.sourceFrame records.sourceCase.entry.frame
      records.sourceCase.header rfl records.sourceNetwork records.sourceTransport records.sourceCase.application
      source rfl application
  · apply checked_IP_frame_describes_native records.logicalFrame
      (records.sourceCase.ready records.configuration).frame records.sourceCase.forwardedHeader
      _ records.logicalNetwork records.logicalTransport records.sourceCase.application logical _ forwardedApplication
    · simp [RoutedMACsecCase.ready, RoutedMACsecCase.filtered, RoutedMACsecCase.routed,
        RoutedMACsecCase.entry, RoutedMACsecCase.forwardedHeader, Records.configuration,
        Config.forwardedFrame, Frame.forwarded, Frame.visibleHeader, Body.visibleHeader]
    · simp [RoutedMACsecCase.ready, RoutedMACsecCase.filtered, RoutedMACsecCase.routed,
        RoutedMACsecCase.entry, Records.configuration, Config.forwardedFrame]

theorem all_three_cases_start_at_a_recorded_arrival_with_decoded_payload :
    ∀ records ∈ [protectedCase, unprotectedAllowed, unprotectedDenied],
      NativeIngressAttachment records.inventory records.sourceCase.entryIface ∧
      records.sourceFrame.Describes records.sourceCase.entry.frame ∧
      records.logicalFrame.Describes (records.sourceCase.ready records.configuration).frame := by
  intro records member
  exact checked_source_frames_bind_native_entry_and_logical_output records (captured_source_checks records member)

end TDN.Imported.BoundaryMACsec
