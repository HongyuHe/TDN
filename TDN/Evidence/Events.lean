import TDN.Evidence.EventTypes

namespace TDN.Imported.Events

set_option maxRecDepth 100000

def objectiveExchange : Evidence.IKEExchangeObservation := ⟨1, 4, 7, 19, 24, 81, "ECP_384", "ML_KEM_1024", ["ML_DSA_87", "ML_DSA_87"], "AES_GCM_16_256", [312, 345], 2, 2, 11, 11, 2, 3⟩

theorem observed_objective_exchange_sequence : Evidence.ObservedObjectiveSequence objectiveExchange := by unfold Evidence.ObservedObjectiveSequence objectiveExchange; decide

def matchingMKA : Evidence.MKAExperiment := ⟨true, [⟨"tcv2k-a", true, 1, 2000, 1, 1, "GCM-AES-256", 0⟩, ⟨"tcv2k-b", true, 1, 2000, 1, 1, "GCM-AES-256", 0⟩], 3, 3⟩

theorem matching_mka_outcome : Evidence.ObservedMatchingMKASuccess matchingMKA := by unfold Evidence.ObservedMatchingMKASuccess matchingMKA; decide

def mismatchedMKA : Evidence.MKAExperiment := ⟨false, [⟨"tcv2k-a", false, 0, 2000, 0, 0, "GCM-AES-256", 5⟩, ⟨"tcv2k-b", false, 0, 2000, 0, 0, "GCM-AES-256", 5⟩], 3, 0⟩

theorem mismatched_mka_outcome : Evidence.ObservedMismatchedMKARefusal mismatchedMKA := by unfold Evidence.ObservedMismatchedMKARefusal mismatchedMKA; decide

end TDN.Imported.Events
