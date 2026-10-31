import TDN.Semantics.Encapsulation

namespace TDN.Targets

inductive EncapsulationPlacement where
  | outerIncomingInterface | internalPseudowire | standalone
  deriving DecidableEq, Repr

structure MACsecCarrier where
  id : Nat
  innerLayer : Bool
  crossesIPNetwork : Bool
  encapsulated : Bool
  protocol : String
  placement : EncapsulationPlacement
  featureSupported : Bool
  standaloneComponent : Option Nat
  standaloneInternalConnectedToInner : Bool
  standaloneExternalConnectedToOuter : Bool
  beforeOuterEncryption : Bool
  deriving DecidableEq, Repr

/-- RG015 permits any AO-approved encapsulation protocol and preserves the supported
built-in/standalone alternatives. Standalone devices retain the explicit Section11.1 obligation. -/
def msc_macsec_encapsulation (carriers : List MACsecCarrier)
    (aoApproved : String → Prop) (section11_1Satisfied : Nat → Prop)
    (generalManagementAndFilteringSelected : Bool)
    (generalManagementAndFiltering : Nat → Prop) : Prop :=
  ∀ carrier ∈ carriers, carrier.innerLayer = true ∨ carrier.crossesIPNetwork = true →
    carrier.encapsulated = true ∧ aoApproved carrier.protocol ∧
    (carrier.innerLayer = true → carrier.beforeOuterEncryption = true) ∧
    (carrier.placement ≠ .standalone → carrier.featureSupported = true) ∧
    (carrier.placement = .standalone →
      ∃ component, carrier.standaloneComponent = some component ∧
        carrier.standaloneInternalConnectedToInner = true ∧
        carrier.standaloneExternalConnectedToOuter = true ∧ section11_1Satisfied component ∧
        (generalManagementAndFilteringSelected = true → generalManagementAndFiltering component))

/-- A protected MACsec frame can serve as the generic carrier body. Intermediate IP forwarding
preserves that whole frame; decapsulation cannot occur at an unconfigured intermediate endpoint. -/
theorem encapsulation_preserves_macsec_body {MACsecFrame : Type}
    (edge : Nat → Nat → Prop) (source destination : Nat) (protectedFrame : MACsecFrame)
    {finish : Encapsulation.State MACsecFrame} {actions : List Encapsulation.Action}
    (run : (Encapsulation.lts edge).MTr
      ⟨source, .wrapped destination protectedFrame⟩ actions finish) :
    finish.frame = .wrapped destination protectedFrame ∨
      (finish.node = destination ∧ finish.frame = .exposed protectedFrame) :=
  Encapsulation.carried_body_preserved_to_endpoint edge source destination protectedFrame run

end TDN.Targets
