import TDN.Targets.Architecture

namespace TDN.Targets

/-- Matching observed bridge attachments place a service on the same selected
network as the client's designated inside interface. Address-prefix equality
alone is not used. Network zoning comes from the declared architecture. -/
theorem service_location_from_shared_bridge
    (networkZone : String → Zone) (insideBridge serviceBridge : String)
    (attachmentsMatch : serviceBridge = insideBridge)
    (insideIsRed : networkZone insideBridge = .red) :
    networkZone serviceBridge = .red := by
  rw [attachmentsMatch]
  exact insideIsRed

end TDN.Targets
