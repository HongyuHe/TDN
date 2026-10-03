import TDN.Network.Authentication
import TDN.Network.ExecutionTrace

/-!
Service placement connects credential retrieval and route witnesses to the
network model. Missing retrieval metadata stays unknown. A complete observed
empty demand set can support a local-CRL deployment, provided admission still
uses a fresh authenticated CRL. Routed trace checks also retain next-hop
information, so a chosen path cannot bypass a router selected by the FIB.
-/
namespace TDN.Network.Services
open Execution

/-- The declared service mechanism is kept separate from live observations.
The concrete instance must compare it with loaded credentials and processes. -/
structure Configuration (Node : Type) where
  device : Node
  externalInterface : String
  localAddress : UInt32
  peerAddress : UInt32
  localProtocols : List String
  revocationDelivery : String
  clock : String
  deriving DecidableEq, BEq, Repr

/-- Every advertised retrieval location contributes a demand. The combined
set includes certificate CDPs, OCSP, issuer URLs, and loaded authority entries.
Absence of an observation yields `none`, which differs from observed emptiness. -/
def retrievalLocations? (audit : CredentialAudit)
    (authorities : Option (List AuthorityConfiguration)) : Option (List String) := do
  let authorities ← authorities
  let certificateLocations ← audit.certificates.mapM fun certificate => do
    let crls ← certificate.crlDistributionPoints
    let ocsp ← certificate.ocspServers
    let issuers ← certificate.issuingCertificateURLs
    pure (crls ++ ocsp ++ issuers)
  pure (certificateLocations.flatten ++ authorities.flatMap fun authority =>
    authority.crlURIs ++ authority.ocspURIs ++
      if authority.certificateURIBase.isEmpty then [] else [authority.certificateURIBase])

/-- Successful admission already identifies a fresh loaded CRL. Requiring an
observed empty retrieval set makes the corresponding service-placement claim
explicit. The checker never replaces missing CRL evidence with network success. -/
theorem local_revocation_supports_admitted_request {Label : Type}
    (policy : Authentication.Policy Label) (audit : CredentialAudit)
    (authorities : Option (List AuthorityConfiguration))
    (localOnly : retrievalLocations? audit authorities = some [])
    (request : Authentication.Request) (accepted : Authentication.admits policy audit request = true) :
    retrievalLocations? audit authorities = some [] ∧
    ∃ certificate ∈ audit.certificates, ∃ crl ∈ audit.crls,
      certificate.fingerprint = request.certificate ∧
      certificate.notBefore ≤ audit.atEpoch ∧ audit.atEpoch ≤ certificate.notAfter ∧
      crl.thisUpdate ≤ audit.atEpoch ∧ audit.atEpoch < crl.nextUpdate ∧
      certificate.serial ∉ crl.revokedSerials :=
  ⟨localOnly, Authentication.admitted_peer_is_current_and_unrevoked policy audit request accepted⟩

variable {Node Message : Type}

def addressesAt (model : Model Node) (endpoint : Endpoint Node) : List UInt32 :=
  ((model.interfaces endpoint.node).filter (fun port => port.name == endpoint.port)).flatMap
    (fun port => port.addresses.map Prefix.address)

def nextAddressedInput (model : Model Node) (states : List (State Node Message)) : Option (State Node Message) :=
  states.find? fun state => state.phase == .input && !(addressesAt model state.location).isEmpty

/-- Addressless switch outputs do not perform a route lookup. Each addressed
output must use its observed route and reach the next-hop address on the next
addressed input. Intermediate wire/switch transitions are checked by the runner. -/
def legRespectsNextHop (model : Model Node) (state : State Node Message)
    (later : List (State Node Message)) : Bool :=
  if state.phase != .output || (addressesAt model state.location).isEmpty then true else
  (model.route state.location.node state.packet.header).any fun route =>
    route.kind == "unicast" && route.output == state.location.port &&
    (nextAddressedInput model later).any fun target =>
      (addressesAt model target.location).contains (route.gateway.getD state.packet.header.destination)

def respectsNextHops (model : Model Node) : List (State Node Message) → Bool
  | [] => true
  | state :: tail => legRespectsNextHop model state tail && respectsNextHops model tail

theorem routed_output_reaches_selected_next_hop (model : Model Node) (state : State Node Message)
    (later : List (State Node Message)) (output : state.phase = .output)
    (addressed : (addressesAt model state.location).isEmpty = false)
    (coherent : legRespectsNextHop model state later = true) :
    ∃ route, model.route state.location.node state.packet.header = some route ∧
      route.kind = "unicast" ∧ route.output = state.location.port ∧
      ∃ target ∈ later, target.phase = .input ∧
        route.gateway.getD state.packet.header.destination ∈ addressesAt model target.location := by
  have guard : (state.phase != .output || (addressesAt model state.location).isEmpty) = false := by
    rw [output, addressed]
    rfl
  simp only [legRespectsNextHop, guard, Bool.false_eq_true, ↓reduceIte] at coherent
  simp only [Option.any_eq_true, Bool.and_eq_true, beq_iff_eq] at coherent
  obtain ⟨route, selected, ⟨kind, port⟩, target, found, reached⟩ := coherent
  have phase : target.phase = .input := by
    have matched := List.find?_some found
    cases phase : target.phase <;> simp_all [nextAddressedInput]
  exact ⟨route, selected, kind, port, target, List.mem_of_find?_eq_some found,
    phase, by simpa using reached⟩

end TDN.Network.Services
