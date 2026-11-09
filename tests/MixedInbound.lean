import TDN.Models.TableDrivenMultiProtocolAuth

open TDN TDN.MultiProtocolForwarding TDN.LayeredFrame

namespace MixedInboundRegression

def ifaces : List DataPlaneForwarding.IfaceData :=
  [{ owner := 0, name := "black", stack := [2, 1] },
   { owner := 0, name := "carrier", stack := [1] }]

def carrier : CarrierIface :=
  { virtualIface := 1, routingIface := 1, transmit := { source := 100, destination := 200, sourcePort := 1701, destinationPort := 1701, peerSession := 8 },
    localSession := 7 }

def unguarded : List DataPlaneForwarding.DeviceData :=
  [{ inputRules := [⟨[], .allow⟩] }]

def authenticated : List DataPlaneForwarding.DeviceData :=
  [{ inputRules := [⟨[.inboundPolicy 200], .allow⟩] }]

/-- A carrier can otherwise move an arbitrary unauthenticated body across the cut. -/
example : ¬ TableDrivenCarrierInputChecks unguarded ifaces [carrier] 2 := by
  unfold TableDrivenCarrierInputChecks
  decide

/-- The real receive-policy guard blocks the unauthenticated carrier path. -/
example : TableDrivenCarrierInputChecks authenticated ifaces [carrier] 2 := by
  unfold TableDrivenCarrierInputChecks
  decide

/-- A permissive fallback cannot be hidden by an empty rule inventory. -/
example : ¬ TableDrivenCarrierInputChecks [{ inputFallback := .allow }] ifaces [carrier] 2 := by
  unfold TableDrivenCarrierInputChecks
  decide

def receivedAssociation : MACsecAssociation := ⟨1, 100, 0, 7⟩
def transmittedAssociation : MACsecAssociation := ⟨99, 100, 0, 123⟩

/-- SCI/AN agree even when arbitrary local generation and role annotations differ. -/
example : SameMACWireIdentity transmittedAssociation receivedAssociation := by decide

def macIface : MACIface :=
  { logicalIface := 1, physicalIface := 0, settings := ⟨true, true, true, 0⟩,
    transmitAssociation := none, receiveAssociations := [receivedAssociation], validateStrict := true }

def config : MultiProtocolForwarding.Config :=
  dataPlaneModelFromRecords [] [] [] [] [] [macIface] []

def body : Body := .ethernet ⟨1, 2, 35061, []⟩
def received : MultiProtocolForwarding.State :=
  { iface := 0, datapathStage := .received, frame := { payload := 42, originDomain := 3, body := .macsec transmittedAssociation body },
    enteredIface := 0, authenticated := [], tracking := "NEW" }

/-- A real receive transition is not suppressed by an untrusted input annotation. -/
example : MultiProtocolForwarding.Step config received .decryptMACsec
    { received with iface := 1, frame := { received.frame with body := body }, authenticated := [] } :=
  MultiProtocolForwarding.Step.decryptMACsec macIface receivedAssociation transmittedAssociation body
    (by decide) rfl rfl rfl (by decide) (by decide)

end MixedInboundRegression
