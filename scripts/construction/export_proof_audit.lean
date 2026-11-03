import TDN
import Lean
import Lean.Util.CollectAxioms

set_option pp.deepTerms true
set_option pp.maxSteps 5000000

open Lean Elab Command Meta

run_cmd do
  let some inputPath ← liftIO <| IO.getEnv "TDN_PROOF_NAMES"
    | throwError "TDN_PROOF_NAMES is required"
  let some outputPath ← liftIO <| IO.getEnv "TDN_PROOF_AUDIT"
    | throwError "TDN_PROOF_AUDIT is required"
  let source ← liftIO <| IO.FS.readFile inputPath
  let roots := (source.splitOn "\n").filterMap fun line =>
    let trimmed := line.trimAscii.toString
    if trimmed.isEmpty then none else some trimmed.toName
  if roots.isEmpty then throwError "At least one proof name is required"
  let environment ← getEnv
  let allowedAxioms := #[``propext, ``Classical.choice, ``Quot.sound]
  let mut rootRecords : Array Json := #[]
  let mut failures : Array String := #[]
  for name in roots do
    let some information := environment.find? name
      | throwError "Unknown proof: {name}"
    unless information.isTheorem do throwError "Expected a theorem: {name}"
    let axioms ← collectAxioms name
    if axioms.any (fun axiomName => !allowedAxioms.contains axiomName) then
      failures := failures.push name.toString
    let (binders, conclusion, conclusionHead) ← liftTermElabM <|
      forallTelescope information.type fun parameters conclusion => do
        let binders ← parameters.mapM fun parameter => do
          let declaration ← parameter.fvarId!.getDecl
          let typeText := (← ppExpr declaration.type).pretty
          return Json.mkObj [
            ("name", toJson declaration.userName.toString),
            ("type", toJson typeText),
            ("is_proposition", toJson (← isProp declaration.type))]
        let headName := match conclusion.getAppFn with
          | .const declarationName _ => some declarationName.toString
          | _ => none
        return (binders, (← ppExpr conclusion).pretty, headName)
    rootRecords := rootRecords.push <| Json.mkObj [
      ("name", toJson name.toString),
      ("binders", toJson binders),
      ("conclusion", toJson conclusion),
      ("conclusion_head", toJson conclusionHead),
      ("axioms", toJson (axioms.map Name.toString))]
  let mut pending := roots.toArray
  let mut seen : NameSet := {}
  let mut records : Array Json := #[]
  let mut index := 0
  while index < pending.size do
    let name := pending[index]!
    index := index + 1
    if seen.contains name then continue
    seen := seen.insert name
    let some information := environment.find? name
      | throwError "Unknown proof dependency: {name}"
    let typeText ← liftTermElabM <| return (← ppExpr information.type).pretty
    let typeDependencies := information.type.getUsedConstants
    let bodyDependencies := match information with
      | .thmInfo declaration => declaration.value.getUsedConstants
      | .defnInfo declaration => declaration.value.getUsedConstants
      | .opaqueInfo declaration => declaration.value.getUsedConstants
      | .inductInfo declaration => declaration.ctors.toArray
      | _ => #[]
    let kind := match information with
      | .thmInfo _ => "theorem"
      | .defnInfo _ => "definition"
      | .opaqueInfo _ => "opaque"
      | .axiomInfo _ => "axiom"
      | .inductInfo _ => "type"
      | .ctorInfo _ => "constructor"
      | .recInfo _ => "recursor"
      | .quotInfo _ => "quotient primitive"
    let moduleName := (environment.getModuleIdxFor? name).map fun moduleIndex =>
      environment.header.moduleNames[moduleIndex.toNat]!.toString
    records := records.push <| Json.mkObj [
      ("name", toJson name.toString),
      ("module", toJson moduleName),
      ("kind", toJson kind),
      ("type", toJson typeText),
      ("type_dependencies", toJson (typeDependencies.map Name.toString)),
      ("body_dependencies", toJson (bodyDependencies.map Name.toString))]
    for dependency in typeDependencies ++ bodyDependencies do
      if dependency.toString.startsWith "TDN." ||
          dependency.toString.startsWith "_private.TDN." then
        pending := pending.push dependency
  liftIO <| IO.FS.writeFile outputPath <| (Json.mkObj [
    ("roots", toJson rootRecords),
    ("declarations", toJson records),
    ("unexpected_axiom_roots", toJson failures)]).pretty ++ "\n"
  if !failures.isEmpty then throwError "Unexpected axioms in {failures}"
  logInfo m!"Audited {roots.length} proofs and {records.size} TDN declarations."
