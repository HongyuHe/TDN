import TDN.Evidence.OuterGrayNativeModel
import TDN.Targets.BoundaryRuleDerivation
import TDN.Targets.BoundaryPeerDerivation
import TDN.Targets.BoundaryControlRules

namespace TDN.Imported.BoundaryNativeModel
open Compliance Targets Targets.Complete OuterGrayNativeModel

structure FirewallBinding where
  firewall : String
  outer : String
  deriving DecidableEq

def redServiceLookup (endpoints : List RedServiceEndpoint) (inner : String)
    (address port : Nat) : Prop :=
  ∃ endpoint ∈ endpoints, endpoint.inner = inner ∧ endpoint.address = address ∧ endpoint.port = port

instance (endpoints : List RedServiceEndpoint) (inner : String) (address port : Nat) :
    Decidable (redServiceLookup endpoints inner address port) := by
  unfold redServiceLookup
  infer_instance

def registeredDeployment (records : Records) (services : List ServiceRegistration)
    (endpoints : List RedServiceEndpoint) (base : Deployment)
    (controls : List BoundaryControlFlow := []) : Deployment :=
  { records.deployment base with
    services := services
    redService := redServiceLookup endpoints
    policyApproved := BoundaryControlApproval controls }

instance (records : Records) (services : List ServiceRegistration)
    (endpoints : List RedServiceEndpoint) (base : Deployment) (controls : List BoundaryControlFlow) (inner : String) (address port : Nat) :
    Decidable ((registeredDeployment records services endpoints base controls).redService inner address port) := by
  change Decidable (redServiceLookup endpoints inner address port)
  infer_instance

instance (records : Records) (services : List ServiceRegistration)
    (endpoints : List RedServiceEndpoint) (base : Deployment) (controls : List BoundaryControlFlow) :
    DecidableRel (registeredDeployment records services endpoints base controls).intendedPeer := by
  intro source destination
  change Decidable (∃ tunnel ∈ records.tunnels, tunnel.sender = source ∧ tunnel.receiver = destination)
  infer_instance

lemma every_declared_Red_endpoint_is_bound (records : Records)
    (services : List ServiceRegistration) (endpoints : List RedServiceEndpoint) (base : Deployment)
    (controls : List BoundaryControlFlow := []) :
    ∀ endpoint ∈ endpoints, endpoint.Bound (registeredDeployment records services endpoints base controls) := by
  intro endpoint member
  exact ⟨endpoint, member, rfl, rfl, rfl⟩

def localOuter (bindings : List FirewallBinding) (firewall : String) : String :=
  ((bindings.find? (fun binding => binding.firewall == firewall)).map FirewallBinding.outer).getD
    "unlisted-local-Outer"

end TDN.Imported.BoundaryNativeModel
