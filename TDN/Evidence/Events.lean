import TDN.Import.Command
import TDN.Evidence.EventTypes

namespace TDN.Imported.Events

set_option maxRecDepth 100000

tdn_data objectiveExchange : Evidence.IKEExchangeObservation from "../../evidence/lean/Events.json" ["TDN.Imported.Events.objectiveExchange"]

theorem observed_objective_exchange_sequence : Evidence.ObservedObjectiveSequence objectiveExchange := by unfold Evidence.ObservedObjectiveSequence objectiveExchange; decide

tdn_data matchingMKA : Evidence.MKAExperiment from "../../evidence/lean/Events.json" ["TDN.Imported.Events.matchingMKA"]

theorem matching_mka_outcome : Evidence.ObservedMatchingMKASuccess matchingMKA := by unfold Evidence.ObservedMatchingMKASuccess matchingMKA; decide

tdn_data mismatchedMKA : Evidence.MKAExperiment from "../../evidence/lean/Events.json" ["TDN.Imported.Events.mismatchedMKA"]

theorem mismatched_mka_outcome : Evidence.ObservedMismatchedMKARefusal mismatchedMKA := by unfold Evidence.ObservedMismatchedMKARefusal mismatchedMKA; decide

end TDN.Imported.Events
