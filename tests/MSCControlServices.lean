import TDN

namespace MSCControlServicesRegression
open TDN.Network TDN.Network.Execution TDN.Network.Services
open TDN.MSC TDN.MSC.Execution TDN.MSC.ExecutionTrace TDN.MSC.ControlServices

def audit : CredentialAudit := (Authentication.audit? "I_A1").getD
  { atEpoch := 0, pemSHA256 := "", anchors := [], certificates := [], crls := [] }

example : retrievalLocations? audit (authorities "I_A1") = some [] := by decide
example : retrievalLocations? audit none = none := by decide
example : retrievalLocations? { audit with certificates := audit.certificates.map (fun certificate =>
    { certificate with ocspServers := none }) } (authorities "I_A1") = none := by decide
example : retrievalLocations? { audit with certificates := audit.certificates.map (fun certificate =>
    { certificate with ocspServers := some ["http://ocsp.example.test/check"] }) }
    (authorities "I_A1") ≠ some [] := by decide

example : retrievalLocations? audit (some [⟨"remote", "CN=remote",
    ["http://crl.example.test/current"], [], ""⟩]) ≠ some [] := by decide

/-- An empty network demand does not supply missing revocation evidence. -/
def peerRequest := ((Authentication.sessions "I_A1").head?.bind (Authentication.sessionRequest? audit)).getD
  { localIdentity := "", remoteIdentity := "", certificate := "", possessionVerified := false }

example : TDN.Network.Authentication.admits (Authentication.policy "I_A1")
    { audit with crls := [] } peerRequest = false := by decide

example : innerPlans.length = 8 ∧ dataPlans.length = 4 := by decide
example : requiredGrayTransits? = some [] := by decide

def examplePlan : Plan := (innerPlans.head?).getD
  { source := "", target := "", targetPort := "", servicePort := 0,
    start := ⟨⟨"", ""⟩, .output, .clear { source := 0, destination := 0, protocol := 0 } none⟩,
    commands := [] }

def redirected : Model String :=
  { model with observed := fun node => (model.observed node).map fun observation =>
      if node == "I_A1" then
        { observation with routes := observation.routes.map fun routes => routes.map fun route =>
            if route.destination == ⟨0x0ac80102, 32⟩ then
              { route with gateway := some 0x0a6401fe }
            else route }
      else observation }

/-- Redirecting the first next hop to a Gray Firewall invalidates the chosen
path certificate even though the old wire/switch command sequence still runs.
The routing check supplies an independent condition beyond physical adjacency. -/
example : ∀ result ∈ (trace examplePlan.start examplePlan.commands).toList,
    respectsNextHops model (examplePlan.start :: result.visited) = true ∧
    respectsNextHops redirected (examplePlan.start :: result.visited) = false := by decide

example (plan : Plan) (member : plan ∈ plans) :
    ∃ result : TDN.Network.ExecutionTrace.Result String Unit,
      TDN.Network.Reach
        (TDN.Network.Without (Step model) (fun state => role? state.location.node = some .grayFirewall))
        plan.start result.last ∧ result.last.location = ⟨plan.target, plan.targetPort⟩ ∧
        result.last.phase = .input ∧ (model.deliver plan.target plan.targetPort result.last.packet).isSome = true ∧
        respectsNextHops model (plan.start :: result.visited) = true :=
  required_service_has_executable_gray_free_path plan member

end MSCControlServicesRegression
