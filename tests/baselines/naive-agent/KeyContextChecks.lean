import TDN.Import.SnapshotLoader

namespace TDN.Benchmark.KeyContexts

abbrev KeyContext := String × String

load_network_records inner : List KeyContext from "evidence.json" ["inner"]
load_network_records outer : List KeyContext from "evidence.json" ["outer"]

set_option Elab.async false
run_cmd do Lean.logInfo m!"TDN_BEGIN {← IO.monoNanosNow}"

lemma active_layers_have_distinct_key_contexts :
    inner ≠ [] ∧ outer ≠ [] ∧ ∀ key ∈ inner, key ∉ outer := by native_decide

run_cmd do Lean.logInfo m!"TDN_END {← IO.monoNanosNow}"

end TDN.Benchmark.KeyContexts
