import TDN
import Lean

open Lean Elab Command

private def conclusionHead : Expr → String
  | .forallE _ _ body _ => conclusionHead body
  | .letE _ _ _ body _ => conclusionHead body
  | .mdata _ body => conclusionHead body
  | body => match body.getAppFn with
    | .const name _ => name.toString
    | _ => ""

private def aliasTarget (value : Expr) (count : Nat := 0) : String :=
  match value with
  | .lam _ _ body _ => aliasTarget body (count + 1)
  | .mdata _ body => aliasTarget body count
  | body =>
    let args := body.getAppArgs
    match body.getAppFn with
    | .const name _ =>
      if args.size == count && (args.toList.zipIdx.all fun (arg, index) =>
          arg == .bvar (count - index - 1)) then name.toString else ""
    | _ => ""

run_cmd do
  let env ← getEnv
  let mut rows : Array Json := #[]
  for (name, info) in env.constants.toList do
    if name.toString.startsWith "TDN." then
      let kind := match info with
        | .thmInfo _ => "theorem"
        | .defnInfo _ => "definition"
        | .axiomInfo _ => "axiom"
        | .inductInfo _ => "inductive"
        | _ => "auxiliary"
      let valueDeps := match info.value? (allowOpaque := true) with
        | some value => value.getUsedConstants.map Name.toString
        | none => #[]
      rows := rows.push <| Json.mkObj [
        ("name", toJson name.toString),
        ("kind", toJson kind),
        ("aliasOf", toJson (match info.value? with
          | some value => aliasTarget value
          | _ => "")),
        ("conclusionHead", toJson (conclusionHead info.type)),
        ("typeDependencies", toJson (info.type.getUsedConstants.map Name.toString)),
        ("valueDependencies", toJson valueDeps)]
  liftIO <| IO.FS.writeFile ".lavish/theorem-hierarchy/lean-dependencies.json"
    (Json.arr rows).pretty
