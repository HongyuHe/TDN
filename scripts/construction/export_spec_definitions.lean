import TDN
import Lean

set_option pp.deepTerms true
set_option pp.maxSteps 5000000
set_option pp.structureInstances.defaults true

open Lean Elab Command Meta

run_cmd do
  let rootPath ← liftIO <| IO.getEnv "TDN_SPEC_NAMES"
  let outputPath ← liftIO <| IO.getEnv "TDN_SPEC_EXPORT"
  let some rootPath := rootPath | throwError "TDN_SPEC_NAMES is required"
  let some outputPath := outputPath | throwError "TDN_SPEC_EXPORT is required"
  let source ← liftIO <| IO.FS.readFile rootPath
  let roots := (source.splitOn "\n").filterMap fun line =>
    let trimmed := line.trimAscii.toString
    if trimmed.isEmpty then none else some trimmed.toName
  let environment ← getEnv
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
      | throwError "Missing specification dependency: {name}"
    let typeText ← liftTermElabM <| return (← ppExpr information.type).pretty
    let mut dependencies := information.type.getUsedConstants
    let mut body := Json.null
    let mut bodyExpression := Json.null
    let kind := match information with
      | .defnInfo _ => "definition"
      | .inductInfo _ => "type"
      | .ctorInfo _ => "constructor"
      | .thmInfo _ => "theorem type only"
      | .opaqueInfo _ => "opaque"
      | .axiomInfo _ => "axiom"
      | .recInfo _ => "recursor"
      | .quotInfo _ => "quotient primitive"
    match information with
    | .defnInfo definition =>
      let text ← liftTermElabM <| return (← ppExpr definition.value).pretty
      body := toJson text
      bodyExpression := toJson (reprStr definition.value)
      dependencies := dependencies ++ definition.value.getUsedConstants
    | .inductInfo definition =>
      dependencies := dependencies ++ definition.ctors.toArray
    | _ => pure ()
    records := records.push <| Json.mkObj [
      ("name", toJson name.toString),
      ("kind", toJson kind),
      ("type", toJson typeText),
      ("type_expression", toJson (reprStr information.type)),
      ("body", body),
      ("body_expression", bodyExpression),
      ("dependencies", toJson (dependencies.map Name.toString))]
    for dependency in dependencies do
      if dependency.toString.startsWith "TDN." ||
          dependency.toString.startsWith "_private.TDN." ||
          dependency.toString.startsWith "Cslib.LTS" ||
          dependency.toString.startsWith "Relation.ReflTransGen" then
        pending := pending.push dependency
  liftIO <| IO.FS.writeFile outputPath <| (Json.mkObj [
    ("roots", toJson (roots.map Name.toString)),
    ("declarations", toJson records)]).pretty ++ "\n"
  logInfo m!"Exported {roots.length} specifications and {records.size} definitions/types."
