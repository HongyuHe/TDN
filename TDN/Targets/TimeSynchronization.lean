import TDN.Targets.ComplianceModel

namespace TDN.Targets.Complete
open Compliance

inductive TimeClientRole where
  | innerEncryption | outerEncryption | grayFirewall
  | managementService (serviceId : String)
  | companionFirewall
  deriving DecidableEq

structure TimeClient where
  component : String
  role : TimeClientRole
  deriving DecidableEq

def TimeClient.Required (d : Deployment) (client : TimeClient) (zone : Zone) : Prop :=
  (∃ device ∈ d.devices, device.id = client.component ∧
    ((client.role = .innerEncryption ∧ device.layer = some .inner ∧ zone = .red) ∨
      (client.role = .outerEncryption ∧ device.layer = some .outer ∧ zone = .gray) ∨
      (client.role = .grayFirewall ∧ device.kind = .grayFirewall ∧ zone = .gray))) ∨
  ∃ service ∈ d.managementServices, client.component = service.device ∧
    client.role = .managementService service.id ∧ zone = service.domain.zone

def RequiresTrustedTime (d : Deployment) (component : String) : Prop :=
  ∃ (client : TimeClient) (zone : Zone), client.component = component ∧ client.Required d zone

def TimeClient.Known (d : Deployment) (client : TimeClient) : Prop :=
  (∃ zone, client.Required d zone) ∨
    (client.role = .companionFirewall ∧ d.IsDevice client.component .innerFirewall)

def ManagementServiceInstance.Bound (d : Deployment)
    (service : ManagementServiceInstance) : Prop :=
  service.id ≠ "" ∧ service.process ≠ "" ∧
  (∃ device ∈ d.devices, device.id = service.device) ∧
  ∃ interface ∈ d.interfaces, interface.id = service.interface ∧
    interface.device = service.device ∧ interface.zone = service.domain.zone ∧
    interface.managementNetwork = true

structure TimeSourceEndpoint where
  device : String
  interface : String
  address : Nat
  protocol : String
  port : Nat
  deriving DecidableEq

def TimeSourceEndpoint.Bound (d : Deployment) (source : TimeSourceEndpoint)
    (zone : Zone) : Prop :=
  source.device ≠ "" ∧ source.interface ≠ "" ∧ source.protocol ≠ "" ∧
  (∃ device ∈ d.devices, device.id = source.device) ∧
  (∃ interface ∈ d.interfaces, interface.id = source.interface ∧
    interface.device = source.device ∧ interface.address = some source.address ∧
    interface.zone = zone ∧ (zone = .gray → interface.managementNetwork = true)) ∧
  ∃ service ∈ d.services, service.device = source.device ∧ service.kind = .time ∧
    service.protocol = source.protocol ∧ service.port = source.port

inductive TimeClockKind where
  | timeOfDay | elapsed
  deriving DecidableEq

structure TimeClockBinding where
  id : String
  client : TimeClient
  clock : String
  clockKind : TimeClockKind
  process : String
  executable : String
  observer : String
  operatingFrom : Nat
  operatingUntil : Nat
  deriving DecidableEq

structure TimeSourceConfiguration where
  id : String
  clock : String
  source : TimeSourceEndpoint
  adjustmentEnabled : Bool
  synchronizerProcess : String
  observer : String
  order : Nat
  maximumRemainingCorrectionNanoseconds : Option Nat
  maximumSkewMilliPpm : Option Nat
  deriving DecidableEq

inductive TimeClockOperation where
  | correction (measuredSourceOffset appliedAdjustment : Int)
  | discipline (process : String)
  deriving DecidableEq

def TimeClockOperation.Valid : TimeClockOperation → Prop
  | .correction offset adjustment => adjustment = offset
  | .discipline process => process ≠ ""

structure TimeClockUpdate where
  id : String
  clock : String
  configuration : String
  source : TimeSourceEndpoint
  operation : TimeClockOperation
  process : String
  observer : String
  order : Nat
  deriving DecidableEq

inductive TimeClockInvalidationKind where
  | manualAdjustment | sourceChange | disciplineStopped | clockReset
  deriving DecidableEq

structure TimeClockInvalidation where
  id : String
  clock : String
  kind : TimeClockInvalidationKind
  observer : String
  order : Nat
  deriving DecidableEq

structure TimeClockUse where
  id : String
  binding : String
  client : TimeClient
  clock : String
  clockKind : TimeClockKind
  process : String
  executable : String
  configuration : String
  source : TimeSourceEndpoint
  update : String
  remainingCorrectionNanoseconds : Option Int
  skewMilliPpm : Option Nat
  observer : String
  order : Nat
  deriving DecidableEq

structure TimeRuntimeCorrespondence where
  managementServicePresent : ManagementServiceInstance → Prop
  clockBound : TimeClockBinding → Prop
  configurationLoaded : TimeSourceConfiguration → Prop
  clockOperationOccurred : TimeClockUpdate → Prop
  clockInvalidated : TimeClockInvalidation → Prop
  clockUsed : TimeClockUse → Prop
  sourceTrusted : TimeSourceEndpoint → Prop

structure TimeServiceRecord where
  binding : String
  source : TimeSourceEndpoint
  configuration : String
  update : String
  deriving DecidableEq

structure TimeObservationInventory where
  bindings : List TimeClockBinding
  configurations : List TimeSourceConfiguration
  updates : List TimeClockUpdate
  invalidations : List TimeClockInvalidation
  uses : List TimeClockUse
  services : List TimeServiceRecord
  runtime : TimeRuntimeCorrespondence

def TimeClockBinding.InScope (binding : TimeClockBinding) (use : TimeClockUse) : Prop :=
  use.client = binding.client ∧ use.process = binding.process ∧
  use.observer = binding.observer ∧ binding.operatingFrom ≤ use.order ∧
    use.order < binding.operatingUntil

def TimeObservationInventory.InventoryBound (observations : TimeObservationInventory)
    (d : Deployment) : Prop :=
  (∀ service, observations.runtime.managementServicePresent service ↔
    service ∈ d.managementServices) ∧
  (∀ service ∈ d.managementServices, ManagementServiceInstance.Bound d service) ∧
  (∀ first ∈ d.managementServices, ∀ second ∈ d.managementServices,
    first.id = second.id → first = second) ∧
  (∀ binding ∈ observations.bindings,
    binding.id ≠ "" ∧ binding.clock ≠ "" ∧ binding.clockKind = .timeOfDay ∧
    binding.process ≠ "" ∧
    binding.executable ≠ "" ∧ binding.observer ≠ "" ∧
    binding.operatingFrom < binding.operatingUntil ∧ binding.client.Known d ∧
    (∀ service ∈ d.managementServices,
      binding.client.role = .managementService service.id →
      binding.client.component = service.device ∧ binding.process = service.process) ∧
    observations.runtime.clockBound binding) ∧
  (∀ binding, observations.runtime.clockBound binding → binding.client.Known d →
    binding ∈ observations.bindings) ∧
  (∀ first ∈ observations.bindings, ∀ second ∈ observations.bindings,
    first.id = second.id → first = second) ∧
  (∀ configuration ∈ observations.configurations,
    configuration.id ≠ "" ∧ configuration.synchronizerProcess ≠ "" ∧
    configuration.observer ≠ "" ∧ observations.runtime.configurationLoaded configuration) ∧
  (∀ first ∈ observations.configurations, ∀ second ∈ observations.configurations,
    first.id = second.id → first = second) ∧
  (∀ update ∈ observations.updates,
    update.id ≠ "" ∧ observations.runtime.clockOperationOccurred update) ∧
  (∀ update, observations.runtime.clockOperationOccurred update →
    (∃ binding ∈ observations.bindings, update.clock = binding.clock ∧
      update.observer = binding.observer ∧ binding.operatingFrom ≤ update.order ∧
      update.order < binding.operatingUntil) → update ∈ observations.updates) ∧
  (∀ first ∈ observations.updates, ∀ second ∈ observations.updates,
    first.id = second.id → first = second) ∧
  (∀ invalidation ∈ observations.invalidations,
    invalidation.id ≠ "" ∧ observations.runtime.clockInvalidated invalidation) ∧
  (∀ invalidation, observations.runtime.clockInvalidated invalidation →
    (∃ binding ∈ observations.bindings, invalidation.clock = binding.clock ∧
      invalidation.observer = binding.observer ∧ binding.operatingFrom ≤ invalidation.order ∧
      invalidation.order < binding.operatingUntil) → invalidation ∈ observations.invalidations) ∧
  (∀ use ∈ observations.uses, use.id ≠ "" ∧ observations.runtime.clockUsed use ∧
    ∃ binding ∈ observations.bindings, binding.InScope use) ∧
  (∀ use, observations.runtime.clockUsed use →
    (∃ binding ∈ observations.bindings, binding.InScope use) → use ∈ observations.uses)

def TimeServiceRecord.ValidUse (record : TimeServiceRecord)
    (observations : TimeObservationInventory) (d : Deployment) (zone : Zone)
    (binding : TimeClockBinding) (use : TimeClockUse) : Prop :=
  record.binding = binding.id ∧ use.binding = binding.id ∧ binding.InScope use ∧
  use.clock = binding.clock ∧ use.clockKind = binding.clockKind ∧ use.process = binding.process ∧
  use.executable = binding.executable ∧
  record.source.Bound d zone ∧ observations.runtime.sourceTrusted record.source ∧
  ∃ configuration ∈ observations.configurations,
    configuration.id = record.configuration ∧
    use.configuration = configuration.id ∧ configuration.clock = binding.clock ∧
    configuration.source = record.source ∧ configuration.adjustmentEnabled = true ∧
    configuration.observer = binding.observer ∧ binding.operatingFrom ≤ configuration.order ∧
    use.source = record.source ∧
    (match configuration.maximumRemainingCorrectionNanoseconds with
      | none => True
      | some maximum => ∃ offset, use.remainingCorrectionNanoseconds = some offset ∧
          offset.natAbs ≤ maximum) ∧
    (match configuration.maximumSkewMilliPpm with
      | none => True
      | some maximum => ∃ skew, use.skewMilliPpm = some skew ∧ skew ≤ maximum) ∧
    ∃ update ∈ observations.updates,
      update.id = record.update ∧ use.update = update.id ∧
      update.configuration = configuration.id ∧ update.clock = binding.clock ∧
      update.source = record.source ∧ update.operation.Valid ∧
      update.process = configuration.synchronizerProcess ∧
      (match update.operation with
        | .correction _ _ => True
        | .discipline process => process = configuration.synchronizerProcess) ∧
      update.observer = binding.observer ∧ configuration.order < update.order ∧
      update.order < use.order ∧
      (∀ later ∈ observations.updates, later.clock = binding.clock →
        later.observer = binding.observer → later.order ≤ use.order →
        later.order ≤ update.order) ∧
      ∀ invalidation ∈ observations.invalidations, invalidation.clock = binding.clock →
        invalidation.observer = binding.observer →
        ¬ (update.order ≤ invalidation.order ∧ invalidation.order ≤ use.order)

def TimeConfigurationForClient (observations : TimeObservationInventory) (d : Deployment)
    (client : TimeClient) (zone : Zone) : Prop :=
  (∃ binding ∈ observations.bindings, binding.client = client) ∧
  ∀ binding ∈ observations.bindings, binding.client = client →
    (∃ use ∈ observations.uses, binding.InScope use) ∧
    ∀ use ∈ observations.uses, binding.InScope use →
      ∃ record ∈ observations.services, record.ValidUse observations d zone binding use

def TrustedTimeConfiguration (observations : TimeObservationInventory)
    (device : Device) (d : Deployment) : Prop :=
  ∀ client zone, client.component = device.id → client.Required d zone →
    TimeConfigurationForClient observations d client zone

end TDN.Targets.Complete
