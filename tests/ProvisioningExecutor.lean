import TDN.Targets.Provisioning

open TDN.Targets

def generation : ProvisioningEvent := {
  component := 1, actor := 7, kind := .generateKeyPair, order := 1
  publicKey := "public-key-reference", certificate := "", issuer := "CA"
  chain := [], outOfBand := true, physicallySecured := false
  configuredPerCP := false, workstationZone := .gray, executor := .worker "worker"
}

def request : ProvisioningEvent := {
  generation with kind := .requestCertificate, order := 2, executor := .component 1
}

/-- The same intended component and key reference cannot hide worker generation. -/
example : ¬ CertificateProvisioningPredecessor generation request :=
  worker_generation_cannot_supply_component_request generation request "worker" rfl rfl

/-- Component-local generation and CSR creation satisfy the predecessor condition. -/
example : CertificateProvisioningPredecessor
    { generation with executor := .component 1 } request := by
  simp [CertificateProvisioningPredecessor, generation, request]

/-- A worker-created CSR also fails the component-local creation condition. -/
example : ¬ CertificateProvisioningPredecessor
    { generation with executor := .component 1 }
    { request with executor := .worker "worker" } := by
  simp [CertificateProvisioningPredecessor, generation, request]
