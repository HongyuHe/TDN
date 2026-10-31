import TDN.Semantics.FiniteMultiProtocolAuthentication

open TDN TDN.MultiProtocolExecution TDN.LayeredFrame

namespace MixedInboundRegression

def ports : List Execution.PortData :=
  [{ owner := 0, name := "black", stack := [2, 1] },
   { owner := 0, name := "carrier", stack := [1] }]

def carrier : CarrierPort :=
  { virtualPort := 1, routingPort := 1, transmit := ⟨100, 200, 1701, 1701, 8⟩,
    localSession := 7 }

def unguarded : List Execution.DeviceData :=
  [{ inputRules := [⟨[], .allow⟩] }]

def authenticated : List Execution.DeviceData :=
  [{ inputRules := [⟨[.inboundPolicy 200], .allow⟩] }]

/-- A carrier can otherwise move an arbitrary unauthenticated body across the cut. -/
example : ¬ FiniteCarrierInputChecks unguarded ports [carrier] 2 := by
  unfold FiniteCarrierInputChecks
  decide

/-- The real receive-policy guard blocks the unauthenticated carrier path. -/
example : FiniteCarrierInputChecks authenticated ports [carrier] 2 := by
  unfold FiniteCarrierInputChecks
  decide

/-- A permissive fallback cannot be hidden by an empty rule inventory. -/
example : ¬ FiniteCarrierInputChecks [{ inputFallback := .allow }] ports [carrier] 2 := by
  unfold FiniteCarrierInputChecks
  decide

def receivedAssociation : MACsecAssociation := ⟨1, 100, 0, 7⟩
def transmittedAssociation : MACsecAssociation := ⟨99, 100, 0, 123⟩

/-- SCI/AN agree even when arbitrary local generation and role annotations differ. -/
example : SameMACWireIdentity transmittedAssociation receivedAssociation := by decide

def macPort : MACPort :=
  { logicalPort := 1, physicalPort := 0, settings := ⟨true, true, true, 0⟩,
    transmitAssociation := none, receiveAssociations := [receivedAssociation], validateStrict := true }

def config : MultiProtocolExecution.Config :=
  finiteConfig [] [] [] [] [] [macPort] []

def body : Body := .ethernet ⟨1, 2, 35061, []⟩
def received : MultiProtocolExecution.State :=
  { port := 0, phase := .received, frame := ⟨42, 3, .macsec transmittedAssociation body⟩,
    enteredPort := 0, authenticated := [], tracking := "NEW" }

/-- A real receive transition is not suppressed by an untrusted input annotation. -/
example : MultiProtocolExecution.Step config received .decryptMACsec
    { received with port := 1, frame := { received.frame with body := body }, authenticated := [] } :=
  MultiProtocolExecution.Step.decryptMACsec macPort receivedAssociation transmittedAssociation body
    (by decide) rfl rfl rfl (by decide) (by decide)

end MixedInboundRegression
