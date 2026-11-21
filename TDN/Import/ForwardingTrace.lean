import TDN.Import.SnapshotLoader
import TDN.Models.RecordedForwarding

namespace TDN.Import
open Lean Elab Command

elab "replay_forwarding_trace " cfg:ident " from " file:str : command => do
  let ns ← getCurrNamespace
  let record := fun (name : String) => Syntax.mkStrLit ((ns ++ Name.mkSimple name).toString)
  let here := (System.FilePath.mk (← getFileName)).parent.getD "."
  let json ← IO.ofExcept <| Json.parse (← IO.FS.readFile (here / file.getString))
  let actionsKey := record "witnessActions"
  let actions : List String ← IO.ofExcept <| (json.getObjVal? actionsKey.getString).bind fromJson?
  if actions.isEmpty then throwErrorAt file "a delivery witness needs at least one forwarding action"
  let fields ← IO.ofExcept json.getObj?
  let stateKeys := fields.toList.filter fun (k, _) => k.startsWith (ns.toString ++ ".witnessState")
  unless stateKeys.length == actions.length + 1 do
    throwError "expected exactly one more recorded state than forwarding actions"
  let state := fun (i : Nat) => mkIdent (Name.mkSimple s!"witnessState{i}")
  let step := fun (i : Nat) => mkIdent (Name.mkSimple s!"witness_step{i}")
  let names := mkIdent (Name.mkSimple "witnessActions")
  elabCommand (← `(load_network_records $names : List TDN.DataPlaneForwarding.ForwardingAction from $file [$actionsKey]))
  for i in [:actions.length + 1] do
    let key := record s!"witnessState{i}"
    elabCommand (← `(load_network_records $(state i) : TDN.DataPlaneForwarding.ForwardingState from $file [$key]))
  for (action, i) in actions.zipIdx do
    let label := mkIdent (``TDN.DataPlaneForwarding.ForwardingAction ++ Name.mkSimple action)
    elabCommand (← `(lemma $(step i) :
        TDN.DataPlaneForwarding.ForwardingStep $cfg $(state i) $label $(state (i + 1)) := by
      apply @TDN.DataPlaneForwarding.RecordedForwarding.step_of_admits $cfg
        (fun _ _ => by unfold $cfg TDN.DataPlaneForwarding.dataPlaneModelFromRecords; infer_instance)
        (fun _ _ _ => by unfold $cfg TDN.DataPlaneForwarding.dataPlaneModelFromRecords; infer_instance)
        (fun _ _ => by unfold $cfg TDN.DataPlaneForwarding.dataPlaneModelFromRecords; infer_instance)
      native_decide))
  elabCommand (← `(lemma $(mkIdent (Name.mkSimple "witness_delivery_endpoints")) :
      $(state 0).datapathStage = .localOutput ∧ ($cfg).canOriginateTraffic $(state 0).iface ∧
      $(state 0).frame.encapLayers = [] ∧ $(state actions.length).datapathStage = .delivered ∧
      $(state actions.length).frame.encapLayers = [] := by
    unfold $cfg TDN.DataPlaneForwarding.dataPlaneModelFromRecords
    native_decide))
  let mut run ← `(Cslib.LTS.MTr.refl)
  for i in (List.range actions.length).reverse do
    run ← `(Cslib.LTS.MTr.stepL $(step i) $run)
  elabCommand (← `(theorem $(mkIdent (Name.mkSimple "positive_delivery_forwarding")) :
    (TDN.DataPlaneForwarding.lts $cfg).MTr $(state 0) $names $(state actions.length) := $run))

end TDN.Import
