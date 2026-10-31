import TDN.Targets.Architecture
import Mathlib.Order.Minimal

namespace TDN.Targets

inductive ComponentRole where
  | inner | outer | innerFirewall | grayFirewall | outerFirewall | authenticationServer
  | ips | infrastructure | other
  deriving DecidableEq, Repr

inductive ProductCategory where
  | vpn | macsec | firewall | authenticationServer | ips | other
  deriving DecidableEq, Repr

structure ProductIdentity where
  manufacturer : String
  model : String
  version : String
  category : ProductCategory
  deriving DecidableEq, Repr

structure Component where
  identity : String
  product : ProductIdentity
  role : ComponentRole
  physicalDevice : String
  osFamily : String
  cryptoManufacturer : String
  cryptoLibrary : String
  evaluatedConfiguration : String
  installedConfiguration : String
  modifications : List String
  deriving DecidableEq, Repr

/-- RG-002 compares exact evaluated configurations and retains the NIAP statement
for each actual modification. Vendor consultation remains a recommendation. -/
def msc_validated_configuration_and_modification (components : List Component)
    (niapStatement : String → String → Prop) : Prop :=
  ∀ component ∈ components,
    component.installedConfiguration = component.evaluatedConfiguration ∧
    ∀ modification ∈ component.modifications, niapStatement component.identity modification

/-- RG-003 compares the exact manufacturer/model/version/category tuple against a
dated authoritative list. The deployment's selected products determine applicability. -/
def msc_listed_product_eligibility (components : List Component)
    (datedList : List ProductIdentity) (ipsSelected : Bool) : Prop :=
  ∀ component ∈ components,
    (component.product.category = .vpn ∨ component.product.category = .macsec ∨
      component.product.category = .firewall ∨
      component.product.category = .authenticationServer ∨
      (ipsSelected = true ∧ component.product.category = .ips)) →
    component.product ∈ datedList

def IndependentProducts (subsidiary : String → String → Prop)
    (approved : String → String → Prop) (a b : Component) : Prop :=
  (a.product.manufacturer ≠ b.product.manufacturer ∧
    ¬ subsidiary a.product.manufacturer b.product.manufacturer ∧
    ¬ subsidiary b.product.manufacturer a.product.manufacturer) ∨
  (a.product.manufacturer = b.product.manufacturer ∧
    a.product.model ≠ b.product.model ∧ approved a.identity b.identity)

def IndependentLibraries (subsidiary : String → String → Prop)
    (approved : String → String → Prop) (a b : Component) : Prop :=
  (a.cryptoManufacturer ≠ b.cryptoManufacturer ∧
    ¬ subsidiary a.cryptoManufacturer b.cryptoManufacturer ∧
    ¬ subsidiary b.cryptoManufacturer a.cryptoManufacturer) ∨
  (a.cryptoManufacturer = b.cryptoManufacturer ∧
    a.cryptoLibrary ≠ b.cryptoLibrary ∧ approved a.cryptoLibrary b.cryptoLibrary)

/-- RG-004 separates product, OS-family, library, and Gray-Firewall obligations.
INT004 scopes every applicable role pair to one solution. Combined inventories may contain
independent solutions; source membership must be complete and independently declared. -/
def msc_implementation_diversity (components : List Component)
    (solutionOf : String → String) (subsidiary productApproval libraryApproval : String → String → Prop) : Prop :=
  (∀ inner ∈ components, ∀ outer ∈ components, inner.role = .inner → outer.role = .outer →
    solutionOf inner.identity = solutionOf outer.identity → IndependentProducts subsidiary productApproval inner outer ∧
    inner.osFamily ≠ outer.osFamily ∧
    IndependentLibraries subsidiary libraryApproval inner outer) ∧
  (∀ firewall ∈ components, ∀ inner ∈ components,
    firewall.role = .grayFirewall → inner.role = .inner →
    solutionOf firewall.identity = solutionOf inner.identity → IndependentProducts subsidiary productApproval firewall inner)

def SeparationRequired (a b : ComponentRole) : Prop :=
  (a = .inner ∧ b = .outer) ∨
  (a = .outerFirewall ∧ b ∈ [.outer, .grayFirewall, .inner]) ∨
  (a = .grayFirewall ∧ b ∈ [.outer, .inner]) ∨
  (a = .innerFirewall ∧ b = .inner)

/-- RG-005 concerns actual physical device identities, not namespace/container names. -/
def msc_physically_distinct_security_components (components : List Component) : Prop :=
  ∀ a ∈ components, ∀ b ∈ components,
    SeparationRequired a.role b.role → a.physicalDevice ≠ b.physicalDevice

/-- A role-to-hardware partition proves separation for any number of component instances.
The partition is checked on the small role set and each instance is bound to actual hardware. -/
theorem physical_separation_from_role_partition (components : List Component)
    (hardwareForRole : ComponentRole → String)
    (bindings : ∀ component ∈ components,
      component.physicalDevice = hardwareForRole component.role)
    (partition : ∀ a b, SeparationRequired a b →
      hardwareForRole a ≠ hardwareForRole b) :
    msc_physically_distinct_security_components components := by
  intro a memberA b memberB required same
  apply partition a.role b.role required
  rw [← bindings a memberA, ← bindings b memberB, same]

/-- A role may span arbitrarily many machines. Only role pairs named by the source
must have disjoint hardware sets. Each concrete instance is checked against its role's set. -/
theorem physical_separation_from_disjoint_role_hardware (components : List Component)
    (hardwareForRole : ComponentRole → List String)
    (bindings : ∀ component ∈ components,
      component.physicalDevice ∈ hardwareForRole component.role)
    (partition : ∀ a b, SeparationRequired a b →
      ∀ hardware ∈ hardwareForRole a, hardware ∉ hardwareForRole b) :
    msc_physically_distinct_security_components components := by
  intro a memberA b memberB required same
  apply partition a.role b.role required a.physicalDevice (bindings a memberA)
  rw [same]
  exact bindings b memberB

/-- A same-OS observation contradicts the OS clause regardless of vendor approvals. -/
theorem shared_os_refutes_diversity (components : List Component)
    (solutionOf : String → String) (subsidiary productApproval libraryApproval : String → String → Prop)
    (inner outer : Component) (hi : inner ∈ components) (ho : outer ∈ components)
    (ri : inner.role = .inner) (ro : outer.role = .outer)
    (sameSolution : solutionOf inner.identity = solutionOf outer.identity)
    (same : inner.osFamily = outer.osFamily) :
    ¬ msc_implementation_diversity components solutionOf subsidiary productApproval libraryApproval := by
  intro requirement
  exact (requirement.1 inner hi outer ho ri ro sameSolution).2.1 same

/-- Co-residence supplies a concrete physical-separation counterexample. -/
theorem shared_device_refutes_separation (components : List Component)
    (a b : Component) (ha : a ∈ components) (hb : b ∈ components)
    (required : SeparationRequired a.role b.role)
    (same : a.physicalDevice = b.physicalDevice) :
    ¬ msc_physically_distinct_security_components components := by
  intro requirement
  exact requirement a ha b hb required same

structure SupplyChainAssessment where
  component : String
  application : String
  process : String
  mitigations : List String
  completed : Bool
  deriving DecidableEq, Repr

/-- RG-006 requires a completed assessment through the AO-approved process for the
actual component/application. The mitigation list can legitimately be empty. -/
def msc_supply_chain_assessment (components : List Component)
    (application : String → String) (assessments : List SupplyChainAssessment)
    (aoApprovedProcess : String → Prop) : Prop :=
  ∀ component ∈ components, ∃ assessment ∈ assessments,
    assessment.component = component.identity ∧
    assessment.application = application component.identity ∧
    assessment.completed = true ∧ aoApprovedProcess assessment.process

structure GrayDomain where
  identity : String
  ownerControlled : Bool
  trustedThirdPartyControlled : Bool
  classifiedPhysicalProtection : Bool
  exposedFields : List String
  deriving DecidableEq, Repr

/-- RG-009 retains classification-authority evidence for exposed Gray information.
The payload's original classification does not itself classify the outer header. -/
def msc_gray_network_classification_boundary (gray : List GrayDomain)
    (redControlledByOwnerOrTrustedParty : Prop)
    (classifiedExposedField : String → String → Prop) : Prop :=
  redControlledByOwnerOrTrustedParty ∧ ∀ domain ∈ gray,
    (domain.ownerControlled = true ∨ domain.trustedThirdPartyControlled = true) ∧
    domain.classifiedPhysicalProtection = true ∧
    ∀ field ∈ domain.exposedFields, ¬ classifiedExposedField domain.identity field

structure MACsecOptions where
  clearVlanEnabled : Bool
  clearVlanSupported : Bool
  xpnEnabled : Bool
  xpnSupported : Bool
  deriving DecidableEq, Repr

/-- RG-016 grants optional choices only where the device supports them. -/
def msc_macsec_optional_clear_vlan_and_xpn (devices : List MACsecOptions) : Prop :=
  ∀ device ∈ devices,
    (device.clearVlanEnabled = true → device.clearVlanSupported = true) ∧
    (device.xpnEnabled = true → device.xpnSupported = true)

/-- The optional-feature requirement is preserved when unsupported options are disabled. -/
theorem macsec_options_of_supported_enablement (devices : List MACsecOptions)
    (vlan : ∀ d ∈ devices, d.clearVlanEnabled = (d.clearVlanEnabled && d.clearVlanSupported))
    (xpn : ∀ d ∈ devices, d.xpnEnabled = (d.xpnEnabled && d.xpnSupported)) :
    msc_macsec_optional_clear_vlan_and_xpn devices := by
  intro d hd
  constructor
  · intro enabled
    have check := vlan d hd
    simpa [enabled] using check.symm
  · intro enabled
    have check := xpn d hd
    simpa [enabled] using check.symm

structure TransecUse where
  publicInternet : Bool
  externalMACsec : Bool
  outerFirewallAttached : Bool
  objectiveSelected : Bool
  enabled : Bool
  deriving DecidableEq, Repr

/-- RG-032 keeps the general Public Internet condition and selected OR-9 objective. -/
def msc_transec_conditions (uses : List TransecUse) : Prop :=
  ∀ use ∈ uses,
    (use.publicInternet = true → use.enabled = true) ∧
    (use.objectiveSelected = true → use.externalMACsec = true →
      use.outerFirewallAttached = true → use.enabled = true)

structure InterfaceExposure (Traffic : Type) where
  used : Bool
  enabled : Bool
  allowed : Set Traffic
  feasible : Set Traffic → Prop

/-- RG-036 uses inclusion-minimal exposure among configurations that preserve the declared
authorized function and environment. INT036 permits incomparable minimal alternatives.
An empty policy must still be feasible; disabling useful traffic does not establish minimality. -/
def msc_minimal_interface_exposure {Traffic : Type}
    (interfaces : List (InterfaceExposure Traffic)) : Prop :=
  ∀ interface ∈ interfaces,
    (interface.used = false → interface.enabled = false) ∧
    Minimal interface.feasible interface.allowed

/-- When functional feasibility is preserved by adding traffic permissions, checking that
every individual permission is necessary proves inclusion minimality. Mathlib supplies the
general set result; the source-specific obligations add unused-interface disabling. -/
theorem minimal_exposure_from_necessary_permissions {Traffic : Type}
    (interfaces : List (InterfaceExposure Traffic))
    (disabled : ∀ interface ∈ interfaces, interface.used = false → interface.enabled = false)
    (functional : ∀ interface ∈ interfaces, Monotone interface.feasible)
    (useful : ∀ interface ∈ interfaces, interface.feasible interface.allowed)
    (necessary : ∀ interface ∈ interfaces, ∀ traffic ∈ interface.allowed,
      ¬ interface.feasible (Set.diff interface.allowed {traffic})) :
    msc_minimal_interface_exposure interfaces := by
  intro interface member
  refine ⟨disabled interface member, ?_⟩
  exact (Set.minimal_iff_forall_sdiff_singleton
    (fun {_ _} h feasibleSubset => functional interface member feasibleSubset h)).mpr
      ⟨useful interface member, necessary interface member⟩

structure ThirdPartyService where
  component : String
  service : String
  enabled : Bool
  blocked : Bool
  objectiveSelected : Bool
  deriving DecidableEq, Repr

/-- RG-037 preserves blocking at threshold and disabling at the selected objective. -/
def msc_outer_third_party_services (services : List ThirdPartyService) : Prop :=
  ∀ service ∈ services, if service.objectiveSelected then service.enabled = false
    else service.blocked = true

/-- A disabled service has no execution that can contact any third-party server. -/
theorem disabled_service_excludes_contact {Service Server : Type}
    (enabled : Service → Prop) (contacts : Service → Server → Prop)
    (requiresEnablement : ∀ s d, contacts s d → enabled s)
    (s : Service) (disabled : ¬ enabled s) : ∀ d, ¬ contacts s d := by
  intro d contact
  exact disabled (requiresEnablement s d contact)

structure SharedOuterAttachment where
  redNetwork : String
  inner : String
  outer : String
  outerPhysicalInterface : String
  enclaveVlanTrunk : Bool
  deriving DecidableEq, Repr

/-- RG-053 checks physical interface uniqueness and excludes serial Inner paths. -/
def msc_shared_outer_interface_topology (attachments : List SharedOuterAttachment)
    (passesThroughInner : String → String → Prop) : Prop :=
  (∀ a ∈ attachments, a.enclaveVlanTrunk = false) ∧
  (∀ a ∈ attachments, ∀ b ∈ attachments,
    a.outer = b.outer → a.redNetwork ≠ b.redNetwork →
    a.outerPhysicalInterface ≠ b.outerPhysicalInterface ∧
    ¬ passesThroughInner a.inner b.inner ∧ ¬ passesThroughInner b.inner a.inner)

/-- RG-054 quantifies every required tunnel pair. A successful sample only supports
the exact operation that was observed and does not define implementation interoperability. -/
def msc_site_interoperability (requiredTunnels : List (String × String))
    (interoperable : String → String → Prop) : Prop :=
  ∀ pair ∈ requiredTunnels, interoperable pair.1 pair.2

structure CombinedCapability where
  requiresGrayFirewall : Bool
  grayFirewallPresent : Bool
  includesEndUserDevices : Bool
  externalInnerFirewallRequirementsMet : Bool
  deriving DecidableEq, Repr

def msc_combined_cp_firewalls (combinations : List CombinedCapability) : Prop :=
  ∀ cp ∈ combinations,
    (cp.requiresGrayFirewall = true → cp.grayFirewallPresent = true) ∧
    (cp.includesEndUserDevices = true → cp.externalInnerFirewallRequirementsMet = true)

/-- RG-056 includes every physical Red egress path, with either permitted protection branch. -/
def msc_approved_red_egress_paths {Path : Type} (physicalRedEgress : Path → Prop)
    (conformingMSC aoApprovedTransitSolution : Path → Prop) : Prop :=
  ∀ path, physicalRedEgress path → conformingMSC path ∨ aoApprovedTransitSolution path

/-- RG-074 permits additions while retaining their applicable component obligations.
High availability is not imposed as an additional unconditional requirement. -/
def msc_redundant_component_permission (added : List Component)
    (parallel : Component → Prop) (applicableRequirement : Component → String → Prop)
    (satisfies : Component → String → Prop) : Prop :=
  ∀ component ∈ added, parallel component ∧
    ∀ requirement, applicableRequirement component requirement → satisfies component requirement

/-- Optional screening is a Black-network function outside the MSC solution boundary.
Other optional components acquire no additional configuration duty merely from CP Section 5.
Applicable duties of a separately selected key-management annex are accounted in that annex. -/
structure AdditionalControl where
  screeningRouter : Bool
  locatedOnBlack : Bool
  insideSolutionBoundary : Bool
  deriving DecidableEq, Repr

/-- RG-075 is permission with a screening-router boundary condition.
It does not invent an opaque list of additional CP obligations for optional components. -/
def msc_additional_control_permissions (controls : List AdditionalControl) : Prop :=
  ∀ control ∈ controls, control.screeningRouter = true →
    control.locatedOnBlack = true ∧ control.insideSolutionBoundary = false

theorem additional_controls_from_black_screening_placement (controls : List AdditionalControl)
    (blackPlacement : ∀ control ∈ controls,
      control.screeningRouter = true → control.locatedOnBlack = true)
    (boundary : ∀ control ∈ controls,
      control.screeningRouter = true → control.insideSolutionBoundary = false) :
    msc_additional_control_permissions controls := by
  intro control member screening
  exact ⟨blackPlacement control member screening, boundary control member screening⟩

end TDN.Targets
