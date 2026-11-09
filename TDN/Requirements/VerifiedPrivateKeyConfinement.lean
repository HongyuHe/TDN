import TDN.Models.KeyStoreConfinementModel
import TDN.Models.StutteringTraceSimulation
import TDN.Requirements.MasterMscRequirementSpecs

namespace TDN.Requirements.Msc
open Compliance

abbrev GatewayKey := String × String
abbrev KeyAction := KeyInterface.Action GatewayKey String String
abbrev KeyEvent := KeyInterface.Event GatewayKey String String
abbrev KeyObject := KeyInterface.Object GatewayKey

def privateEvent : NetworkEvent → List KeyEvent
  | .privateKeyExport gateway key interface => [.export (gateway, key) interface]
  | .privateKeyRead gateway key principal => [.read (gateway, key) principal]
  | _ => []

def protectedGatewayKey (keys : List PrivateKey) (identity : GatewayKey) : Prop :=
  ∃ entry ∈ keys, identity = (entry.gateway, entry.id)

lemma private_export_projects {events : List NetworkEvent} {gateway key interface : String}
    (member : NetworkEvent.privateKeyExport gateway key interface ∈ events) :
    KeyInterface.Event.export (gateway, key) interface ∈ events.flatMap privateEvent :=
  List.mem_flatMap.mpr ⟨_, member, List.mem_singleton_self _⟩

lemma private_read_projects {events : List NetworkEvent} {gateway key principal : String}
    (member : NetworkEvent.privateKeyRead gateway key principal ∈ events) :
    KeyInterface.Event.read (gateway, key) principal ∈ events.flatMap privateEvent :=
  List.mem_flatMap.mpr ⟨_, member, List.mem_singleton_self _⟩

lemma private_trace_projection {S A : Type} (model : ForwardingModel S A)
    (actionOf : A → KeyAction) (setup : List KeyAction)
    (history : model.history.Events.flatMap privateEvent = setup.flatMap KeyInterface.Action.events)
    (events : ∀ action, (model.events action).flatMap privateEvent = (actionOf action).events)
    (actions : List A) :
    (model.TraceEvents actions).flatMap privateEvent =
      (setup ++ actions.map actionOf).flatMap KeyInterface.Action.events := by
  rw [ForwardingModel.TraceEvents, List.flatMap_append, history, List.flatMap_append]
  congr 1
  simp only [List.flatMap_assoc, List.flatMap_map]
  apply List.flatMap_congr
  intro action _
  exact events action

theorem vpn_private_key_confinement_from_interface_steps {S A : Type}
    (d : Deployment) (model : ForwardingModel S A)
    (keys : List PrivateKey) (objectiveSelected : String → Bool)
    (policies : List MandatoryKeyPolicy)
    (readers : GatewayKey → Finset String)
    (stateOf : S → List KeyObject) (actionOf : A → KeyAction)
    (initialStore historyStore : List KeyObject) (setup : List KeyAction)
    (stored : ∀ gateway key,
      d.storedVPNKey gateway key ↔ ∃ entry ∈ keys, entry.gateway = gateway ∧ entry.id = key)
    (attributes : KeyInterface.StoreSafe (protectedGatewayKey keys) initialStore)
    (setupRun : (KeyInterface.system (protectedGatewayKey keys)
      (fun identity principal => principal ∈ readers identity)).MTr initialStore setup historyStore)
    (initial : ∀ start, model.initial start → stateOf start = historyStore)
    (steps : ∀ before action after, model.system.Tr before action after →
      KeyInterface.Step (protectedGatewayKey keys)
        (fun identity principal => principal ∈ readers identity)
        (stateOf before) (actionOf action) (stateOf after))
    (history : model.history.Events.flatMap privateEvent = setup.flatMap KeyInterface.Action.events)
    (events : ∀ action, (model.events action).flatMap privateEvent = (actionOf action).events)
    (selectedReaders : ∀ key ∈ keys, objectiveSelected key.gateway = true →
      readers (key.gateway, key.id) ⊆ {key.gateway})
    (policyBinding : ∀ key ∈ keys, objectiveSelected key.gateway = true →
      ∃ policy ∈ policies, policy.gateway = key.gateway ∧ policy.enforced = true ∧
        ∀ principal, policy.permits principal key.id ↔ principal ∈ readers (key.gateway, key.id)) :
    msc_vpn_private_key_confinement d model keys objectiveSelected policies := by
  have projectedRun (start : S) (actions : List A) (finish : S)
      (begins : model.initial start) (run : model.system.MTr start actions finish) :
      (KeyInterface.system (protectedGatewayKey keys)
        (fun identity principal => principal ∈ readers identity)).MTr
        initialStore (setup ++ actions.map actionOf) (stateOf finish) := by
    have projected := TraceProjection.project_forwarding model.system
      (KeyInterface.system (protectedGatewayKey keys)
        (fun identity principal => principal ∈ readers identity))
      stateOf actionOf steps run
    rw [initial start begins] at projected
    exact (Cslib.LTS.MTr.append_iff _).mpr ⟨historyStore, setupRun, projected⟩
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro gateway key _
    exact stored gateway key
  · intro start actions finish begins run key member _ interface exported
    have protectedKey : protectedGatewayKey keys (key.gateway, key.id) :=
      ⟨key, member, rfl⟩
    have projected := private_export_projects exported
    rw [private_trace_projection model actionOf setup history events actions] at projected
    exact KeyInterface.protected_exports_impossible
      (projectedRun start actions finish begins run) attributes protectedKey interface projected
  · intro key member _ selected
    obtain ⟨policy, present, gateway, enforced, binding⟩ := policyBinding key member selected
    refine ⟨policy, present, gateway, enforced, ?_⟩
    intro principal permission
    exact Finset.mem_singleton.mp (selectedReaders key member selected ((binding principal).mp permission))
  · intro start actions finish begins run key member _ selected principal read
    have projected := private_read_projects read
    rw [private_trace_projection model actionOf setup history events actions] at projected
    have authorized := KeyInterface.all_reads_authorized
      (projectedRun start actions finish begins run) projected
    exact Finset.mem_singleton.mp (selectedReaders key member selected authorized)

end TDN.Requirements.Msc
