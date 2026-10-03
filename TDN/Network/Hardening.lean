import TDN.Network.Operational

/-!
Appliance hardening combines a selected policy with retained configuration.
The policy is supplied independently of the observed values. The generic
definitions have no MSC device names, topology, or fixed population size.

Startup interpretation deliberately supports a small command language. Its
local operations represent the audited entrypoint's loopback setup, stale PID
cleanup, and idle command. A remote configuration action records a network
read. An unknown action can produce any effect, so it cannot pass the local
startup certificate. The importer and the interpretation of these primitives
remain trusted; the proof covers all traces of the resulting program.
-/
namespace TDN.Network.Hardening

inductive StartupAction where
  | loopbackUp | clearStalePID | idle
  | startSwitch (configurationPeers : List String)
  | remoteConfiguration (source : String)
  | unknown (command : String)
  deriving DecidableEq, BEq, Repr

def StartupAction.localOnly : StartupAction → Bool
  | .loopbackUp | .clearStalePID | .idle => true
  | .startSwitch peers => peers.isEmpty
  | .remoteConfiguration _ | .unknown _ => false

inductive StartupEffect where
  | local
  | networkConfiguration (source : String)
  deriving DecidableEq, BEq, Repr

def StartupAction.permits (action : StartupAction) (effect : StartupEffect) : Prop :=
  match action with
  | .loopbackUp | .clearStalePID | .idle => effect = .local
  | .startSwitch peers => if peers.isEmpty then effect = .local else True
  | .remoteConfiguration source => effect = .networkConfiguration source
  | .unknown _ => True

inductive StartupTrace : List StartupAction → List StartupEffect → Prop where
  | done : StartupTrace [] []
  | step {action actions effect effects} :
      action.permits effect → StartupTrace actions effects →
      StartupTrace (action :: actions) (effect :: effects)

def localStartup (program : List StartupAction) : Bool :=
  program.all StartupAction.localOnly

/-- A finite certificate over every startup action covers every permitted
execution, including the conservative behavior assigned to unknown commands. -/
theorem local_startup_has_no_network_configuration
    {program : List StartupAction} {effects : List StartupEffect}
    (safe : localStartup program = true) (execution : StartupTrace program effects) :
    ∀ effect ∈ effects, effect = .local := by
  induction execution with
  | done => simp
  | @step action actions effect effects permitted execution ih =>
    have parts : action.localOnly = true ∧ localStartup actions = true := by
      simpa [localStartup] using safe
    have localEffect : effect = .local := by
      cases action <;> simp_all [StartupAction.localOnly, StartupAction.permits]
    intro candidate member
    rcases List.mem_cons.mp member with same | later
    · simpa [same] using localEffect
    · exact ih parts.2 candidate later

structure Resolver where
  servers : List UInt32
  hostSources : List String
  deriving DecidableEq, BEq, Repr

structure StartupContainer where
  name : String
  entrypoint : List String
  command : List String
  script : String
  program : List StartupAction
  resolver : Resolver
  deriving DecidableEq, BEq, Repr

structure NamespaceProcess where
  pid : Nat
  executable : String
  name : String
  deriving DecidableEq, BEq, Repr

structure ApplianceObservation where
  device : String
  containers : List StartupContainer
  processes : List NamespaceProcess
  workerBefore : Nat
  workerAfter : Nat
  deviceClock : Nat
  ntpSynchronized : Bool
  deriving DecidableEq, BEq, Repr

inductive DNSPolicy where
  | specified (servers : List UInt32)
  | disabled
  deriving DecidableEq, BEq, Repr

/-- The disabled branch concerns the modeled system name resolver. Applications
that implement their own DNS transport require a separate traffic policy. -/
def DNSPolicy.accepts (policy : DNSPolicy) (resolver : Resolver) : Bool :=
  match policy with
  | .specified allowed => !resolver.servers.isEmpty &&
      resolver.servers.all (fun address => allowed.contains address) &&
      resolver.hostSources.all (fun source => source == "files" || source == "dns")
  | .disabled => resolver.servers.isEmpty && resolver.hostSources == ["files"]

theorem specified_dns_queries_target_selected_servers
    (allowed : List UInt32) (resolver : Resolver)
    (checked : (DNSPolicy.specified allowed).accepts resolver = true)
    (target : UInt32) (query : target ∈ resolver.servers) : target ∈ allowed := by
  simp only [DNSPolicy.accepts, Bool.and_eq_true, List.all_eq_true] at checked
  simpa using checked.1.2 target query

def interfaceUsed (approved : List String) (port : ObservedInterface) : Bool :=
  !port.up || approved.contains port.name

/-- A complete observed interface inventory supplies the finite certificate.
Every active interface must have an explicit purpose in the selected policy. -/
theorem unused_interface_is_disabled (approved : List String)
    (ports : List ObservedInterface)
    (checked : ports.all (interfaceUsed approved) = true)
    (port : ObservedInterface) (member : port ∈ ports)
    (unused : port.name ∉ approved) : port.up = false := by
  have allowed := List.all_eq_true.mp checked port member
  simpa [interfaceUsed, unused] using allowed

end TDN.Network.Hardening
