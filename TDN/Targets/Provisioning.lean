import TDN.Targets.Management

namespace TDN.Targets

inductive ProvisioningKind where
  | configure | generateKeyPair | requestCertificate | signCertificate | installCertificate | firstUse
  deriving DecidableEq, Repr

/-- The component named in a certificate can differ from the machine that ran
the generation command. Record that distinction explicitly. A worker prepares
the experiment; a component executes within the modeled device boundary. -/
inductive ProvisioningExecutor where
  | component (id : Nat)
  | worker (name : String)
  | unobserved
  deriving DecidableEq, Repr

/-- Order is a causally ordered event index. It is not a duration or wall-clock timestamp.
Public-key and certificate identifiers are hashes of actual public material. -/
structure ProvisioningEvent where
  component : Nat
  actor : Nat
  kind : ProvisioningKind
  order : Nat
  publicKey : String
  certificate : String
  issuer : String
  chain : List String
  outOfBand : Bool
  physicallySecured : Bool
  configuredPerCP : Bool
  workstationZone : ManagementZone
  /-- Execution location is observed or source-bound independently of the intended
  certificate subject. Missing location evidence never defaults to the component. -/
  executor : ProvisioningExecutor := .unobserved
  deriving DecidableEq, Repr

def CertificateProvisioningTrigger (event : ProvisioningEvent) : Prop :=
  event.kind ∈ [.requestCertificate, .signCertificate, .installCertificate]

def CertificateProvisioningPredecessor (before after : ProvisioningEvent) : Prop :=
  before.component = after.component ∧ before.order < after.order ∧
  before.publicKey = after.publicKey ∧
  match after.kind with
  | .requestCertificate => before.kind = .generateKeyPair ∧
      before.executor = .component before.component ∧
      after.executor = .component after.component
  | .signCertificate => before.kind = .requestCertificate ∧ before.issuer = after.issuer
  | .installCertificate => before.kind = .signCertificate ∧
      before.certificate = after.certificate ∧ before.issuer = after.issuer
  | _ => False

/-- Naming the intended certificate subject does not establish where the key was
generated. A worker-origin event cannot satisfy the component-generation clause. -/
lemma worker_generation_cannot_supply_component_request
    (before after : ProvisioningEvent) (worker : String)
    (external : before.executor = .worker worker)
    (request : after.kind = .requestCertificate) :
    ¬ CertificateProvisioningPredecessor before after := by
  intro prior
  simp only [CertificateProvisioningPredecessor, request] at prior
  have generatedHere : before.executor = .component before.component := prior.2.2.2.2.1
  rw [external] at generatedHere
  cases generatedHere

def msc_authorized_initial_provisioning (components : List ManagementComponent)
    (events : List ProvisioningEvent) (authorizedAdministrator : Nat → Prop)
    (appropriateAuthority : Nat → String → Prop)
    (validCertificateChain : String → List String → Prop) : Prop :=
  (∀ use ∈ events, use.kind = .firstUse →
    ∃ configuration ∈ events, configuration.component = use.component ∧
      configuration.kind = .configure ∧ configuration.order < use.order ∧
      configuration.outOfBand = true ∧ configuration.physicallySecured = true ∧
      configuration.configuredPerCP = true ∧ authorizedAdministrator configuration.actor) ∧
  (∀ component ∈ components, component.certificateAuthentication = true →
    ∃ installation ∈ events, installation.component = component.id ∧
      installation.kind = .installCertificate ∧ installation.certificate ≠ "" ∧
      validCertificateChain installation.certificate installation.chain ∧
      appropriateAuthority component.id installation.issuer ∧
      ∀ use ∈ events, use.component = component.id → use.kind = .firstUse →
        installation.order < use.order) ∧
  Admission.HasPrerequisites CertificateProvisioningTrigger CertificateProvisioningPredecessor events ∧
  (∀ event ∈ events, event.kind ∈ [.configure, .requestCertificate, .installCertificate] →
    authorizedAdministrator event.actor) ∧
  (∀ event ∈ events, event.kind = .requestCertificate →
    event.publicKey ≠ "" ∧ appropriateAuthority event.component event.issuer ∧
    ∀ component ∈ components, component.id = event.component → component.role = .outer →
      event.workstationZone = .gray) ∧
  ∀ first ∈ events, ∀ second ∈ events,
    first.kind = .installCertificate → second.kind = .installCertificate →
    first.component ≠ second.component → first.certificate ≠ second.certificate

/-- Admitted certificate installation has an earlier matching signing request and key generation.
Each link is derived from a different local guard in the retained history. -/
theorem installed_certificate_has_component_key_generation (events actions : List ProvisioningEvent)
    (run : (Admission.lts CertificateProvisioningTrigger CertificateProvisioningPredecessor).MTr
      [] actions events)
    (installation : ProvisioningEvent) (member : installation ∈ events)
    (kind : installation.kind = .installCertificate) :
    ∃ generation ∈ events, generation.kind = .generateKeyPair ∧
      generation.component = installation.component ∧
      generation.publicKey = installation.publicKey ∧ generation.order < installation.order ∧
      generation.executor = .component installation.component := by
  have valid := Admission.all_admitted_events_have_prerequisites _ _ run
  obtain ⟨signed, signedMember, signedBefore⟩ := valid installation member (by
    simp [CertificateProvisioningTrigger, kind])
  have signedFacts : signed.component = installation.component ∧
      signed.order < installation.order ∧ signed.publicKey = installation.publicKey ∧
      signed.kind = .signCertificate ∧ signed.certificate = installation.certificate ∧
      signed.issuer = installation.issuer := by
    simpa [CertificateProvisioningPredecessor, kind] using signedBefore
  obtain ⟨requested, requestedMember, requestedBefore⟩ := valid signed signedMember (by
    simp [CertificateProvisioningTrigger, signedFacts.2.2.2.1])
  have requestedFacts : requested.component = signed.component ∧ requested.order < signed.order ∧
      requested.publicKey = signed.publicKey ∧ requested.kind = .requestCertificate ∧
      requested.issuer = signed.issuer := by
    simpa [CertificateProvisioningPredecessor, signedFacts.2.2.2.1] using requestedBefore
  obtain ⟨generated, generatedMember, generatedBefore⟩ := valid requested requestedMember (by
    simp [CertificateProvisioningTrigger, requestedFacts.2.2.2.1])
  have generatedFacts : generated.component = requested.component ∧
      generated.order < requested.order ∧ generated.publicKey = requested.publicKey ∧
      generated.kind = .generateKeyPair ∧
      generated.executor = .component generated.component ∧
      requested.executor = .component requested.component := by
    simpa [CertificateProvisioningPredecessor, requestedFacts.2.2.2.1] using generatedBefore
  have sameComponent := generatedFacts.1.trans (requestedFacts.1.trans signedFacts.1)
  exact ⟨generated, generatedMember, generatedFacts.2.2.2.1,
    sameComponent,
    generatedFacts.2.2.1.trans (requestedFacts.2.2.1.trans signedFacts.2.2.1),
    Nat.lt_trans generatedFacts.2.1 (Nat.lt_trans requestedFacts.2.1 signedFacts.2.1),
    by simpa [sameComponent] using generatedFacts.2.2.2.2.1⟩

/-- The original ancestry statement remains available. Its premise now also
checks that the component generated the key and CSR, as CP section6.1 requires. -/
theorem installed_certificate_has_key_generation (events actions : List ProvisioningEvent)
    (run : (Admission.lts CertificateProvisioningTrigger CertificateProvisioningPredecessor).MTr
      [] actions events)
    (installation : ProvisioningEvent) (member : installation ∈ events)
    (kind : installation.kind = .installCertificate) :
    ∃ generation ∈ events, generation.kind = .generateKeyPair ∧
      generation.component = installation.component ∧
      generation.publicKey = installation.publicKey ∧ generation.order < installation.order := by
  obtain ⟨generation, recorded, generated, component, publicKey, earlier, executor⟩ :=
    installed_certificate_has_component_key_generation events actions run installation member kind
  exact ⟨generation, recorded, generated, component, publicKey, earlier⟩

end TDN.Targets
