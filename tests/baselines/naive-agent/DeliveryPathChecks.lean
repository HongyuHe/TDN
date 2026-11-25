import TDN.Import.SnapshotLoader
import TDN.Models.RecordedForwarding

namespace TDN.Benchmark.Delivery
open DataPlaneForwarding

set_option Elab.async false
set_option maxRecDepth 100000

structure Demand where
  sourceIface : Nat
  destinationIface : Nat
  sourceAddress : Nat
  destinationAddress : Nat
  deriving DecidableEq, BEq

structure Path where
  demand : Demand
  start : ForwardingState
  steps : List (ForwardingAction × ForwardingState)

structure ManagementService where
  iface : Nat
  sourceAddress : Nat
  destinationAddress : Nat
  sourcePort : Nat
  destinationPort : Nat

load_network_records devices : List DeviceData from "evidence.json" ["devices"]
load_network_records ifaces : List IfaceData from "evidence.json" ["ports"]
load_network_records routes : List FibRoute from "evidence.json" ["routes"]
load_network_records links : List (Nat × Nat) from "evidence.json" ["links"]
load_network_records switches : List (Nat × Nat) from "evidence.json" ["bridges"]
load_network_records demands : List Demand from "evidence.json" ["demands"]
load_network_records paths : List Path from "evidence.json" ["paths"]
load_network_records managementServices : List ManagementService from "evidence.json" ["managementServices"]

def model := dataPlaneModelFromRecords devices ifaces routes links switches

instance (i j : Nat) : Decidable (model.link i j) := by unfold model dataPlaneModelFromRecords; infer_instance
instance (i j : Nat) (p : PacketPolicy.Packet) : Decidable (model.bridging i j p) := by unfold model dataPlaneModelFromRecords; infer_instance
instance (i a : Nat) : Decidable (model.localAddress i a) := by unfold model dataPlaneModelFromRecords; infer_instance
instance (i : Nat) : Decidable (model.canOriginateTraffic i) := by unfold model dataPlaneModelFromRecords; infer_instance

def accepted (net : DataPlaneModel) [∀ i j, Decidable (net.link i j)]
    [∀ i j p, Decidable (net.bridging i j p)] [∀ i a, Decidable (net.localAddress i a)]
    (start : ForwardingState) : List (ForwardingAction × ForwardingState) → Bool
  | [] => true
  | (a,t) :: rest => RecordedForwarding.admits net start a t && accepted net t rest

def finish (start : ForwardingState) : List (ForwardingAction × ForwardingState) → ForwardingState
  | [] => start
  | (_,t) :: rest => finish t rest

theorem accepted_path_is_execution (net : DataPlaneModel) [∀ i j, Decidable (net.link i j)]
    [∀ i j p, Decidable (net.bridging i j p)] [∀ i a, Decidable (net.localAddress i a)]
    (start : ForwardingState) (steps : List (ForwardingAction × ForwardingState))
    (ok : accepted net start steps = true) : (lts net).MTr start (steps.map Prod.fst) (finish start steps) := by
  induction steps generalizing start with
  | nil => exact .refl
  | cons head rest ih =>
    obtain ⟨action, next⟩ := head
    obtain ⟨first, tail⟩ := Bool.and_eq_true_iff.mp ok
    exact .stepL (RecordedForwarding.step_of_admits net first) (ih next tail)

def endpointsMatch (path : Path) : Bool :=
  let first := path.start
  let last := finish first path.steps
  let demand := path.demand
  decide (first.datapathStage = .localOutput ∧ first.iface = demand.sourceIface ∧
    model.canOriginateTraffic first.iface ∧ first.frame.encapLayers = [] ∧
    first.frame.packet.source = demand.sourceAddress ∧ first.frame.packet.destination = demand.destinationAddress ∧
    last.datapathStage = .delivered ∧ last.iface = demand.destinationIface ∧ last.frame.encapLayers = [] ∧
    last.frame.packet.source = demand.sourceAddress ∧ last.frame.packet.destination = demand.destinationAddress)

def managementRequest (service : ManagementService) : PacketPolicy.Packet where
  source := service.sourceAddress
  destination := service.destinationAddress
  protocol := "tcp"
  ingress := model.interfaceName service.iface
  egress := ""
  sourcePort := service.sourcePort
  destinationPort := service.destinationPort
  ipv4HeaderWords := 5
  matchedInboundPolicyIds := []
  matchedOutboundPolicyIds := []
  connectionState := "NEW"

def managementAccepted (service : ManagementService) : Prop :=
  model.localAddress service.iface service.destinationAddress ∧
  PacketPolicy.AclAllows (model.inputRules service.iface) (model.inputFallback service.iface)
    (managementRequest service)

instance (service : ManagementService) : Decidable (managementAccepted service) := by
  unfold managementAccepted PacketPolicy.AclAllows
  infer_instance

run_cmd do Lean.logInfo m!"TDN_BEGIN {← IO.monoNanosNow}"

lemma intended_pairs_have_witnesses : demands ≠ [] ∧ paths.map Path.demand = demands ∧
    ∀ path ∈ paths, endpointsMatch path = true := by native_decide

lemma permitted_steps : ∀ path ∈ paths, accepted model path.start path.steps = true := by native_decide

lemma approved_management_input : ∀ service ∈ managementServices, managementAccepted service := by native_decide

theorem captured_delivery_execution (path : Path) (listed : path ∈ paths) :
    (lts model).MTr path.start (path.steps.map Prod.fst) (finish path.start path.steps) :=
  accepted_path_is_execution model path.start path.steps (permitted_steps path listed)

run_cmd do Lean.logInfo m!"TDN_END {← IO.monoNanosNow}"

def failedSteps (start : ForwardingState) : List (ForwardingAction × ForwardingState) → List (Nat × Nat × String)
  | [] => []
  | (a,t) :: rest =>
    let next := (failedSteps t rest).map fun (i,p,s) => (i+1,p,s)
    if RecordedForwarding.admits model start a t then next else (0,start.iface,reprStr a) :: next

#eval paths.map fun path => (path.demand.sourceIface, path.demand.destinationIface, failedSteps path.start path.steps)

end TDN.Benchmark.Delivery
