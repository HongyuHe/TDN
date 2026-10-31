import TDN.Targets.Provisioning

namespace TDN.Imported.FreshProvisioningLocations
open Targets

def observedExecutors : List (Nat × ProvisioningExecutor) := [(0, ProvisioningExecutor.worker "experiment-worker"), (1, ProvisioningExecutor.worker "experiment-worker")]
def observedOrder : List (Nat × Nat × Nat) := [(39, 40, 41), (39, 40, 41)]

lemma generation_request_signing_order : ∀ row ∈ observedOrder,
    row.1 < row.2.1 ∧ row.2.1 < row.2.2 := by decide

lemma generation_is_external : ∀ row ∈ observedExecutors,
    row.2 = .worker "experiment-worker" := by decide

/-- These observations cannot discharge the component-owned generation premise.
The theorem preserves the failed requirement instead of relabeling the worker. -/
theorem recorded_worker_generation_does_not_admit_component_request
    (row : Nat × ProvisioningExecutor) (member : row ∈ observedExecutors)
    (generation request : ProvisioningEvent) (location : generation.executor = row.2)
    (kind : request.kind = .requestCertificate) :
    ¬ CertificateProvisioningPredecessor generation request := by
  exact worker_generation_cannot_supply_component_request generation request "experiment-worker"
    (location.trans (generation_is_external row member)) kind

end TDN.Imported.FreshProvisioningLocations
