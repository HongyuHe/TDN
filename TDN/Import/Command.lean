import Lean
import Lean.Elab.Deriving.ToExpr
import Mathlib.Data.Finset.Sort

/-!
`tdn_data name : Type from "file.json" ["record"]` reads structured JSON and
adds an ordinary definition. The decoder is selected by the declared Lean type.
The round-trip check rejects extra fields and other data the decoder would discard.
The kernel checks the resulting definition. All proofs remain ordinary Lean proofs.
-/
namespace TDN.Import
open Lean Elab Command Meta

instance : ToJson UInt8 where
  toJson value := toJson value.toNat

instance : FromJson UInt8 where
  fromJson? json := do
    let value : Nat ← fromJson? json
    if value < 256 then pure value.toUInt8
    else throw s!"byte {value} is outside 0..255"

instance {n : Nat} : ToJson (Fin n) where
  toJson value := toJson value.val

instance {n : Nat} : FromJson (Fin n) where
  fromJson? json := do
    let value : Nat ← fromJson? json
    if h : value < n then pure ⟨value, h⟩
    else throw s!"index {value} is outside Fin {n}"

instance : ToJson (Finset String) where
  toJson value := toJson (value.sort (· ≤ ·))

instance : FromJson (Finset String) where
  fromJson? json := do
    let values : List String ← fromJson? json
    if values.Nodup then pure values.toFinset else throw "duplicate set member"

instance : ToExpr (Finset String) where
  toTypeExpr := mkApp (mkConst ``Finset [Level.zero]) (mkConst ``String)
  toExpr value := mkApp3 (mkConst ``List.toFinset [Level.zero])
    (mkConst ``String) (mkConst ``instDecidableEqString) (toExpr (value.sort (· ≤ ·)))

set_option linter.checkUnivs false in
deriving instance ToJson, FromJson, ToExpr for Sum

initialize derivedCodecTypes : SimplePersistentEnvExtension Name NameSet ←
  registerSimplePersistentEnvExtension {
    name := `TDN.Import.derivedCodecTypes
    addEntryFn := fun state name => state.insert name
    addImportedFn := fun entries => entries.foldl (fun state names =>
      names.foldl (fun state name => state.insert name) state) {}
  }

private partial def deriveCodecs (name : Name) (visited : NameSet := {}) : CommandElabM NameSet := do
  if visited.contains name then return visited
  let visited := visited.insert name
  let env ← getEnv
  if (derivedCodecTypes.getState env).contains name then return visited
  let some (.inductInfo info) := env.find? name | return visited
  if !(`TDN).isPrefixOf name then return visited
  let mut visited := visited
  for ctor in info.ctors do
    let some (.ctorInfo ci) := env.find? ctor | continue
    let deps := ci.type.getUsedConstants
    for dep in deps do
      if dep != name then visited ← deriveCodecs dep visited
  for cls in [``ToJson, ``FromJson, ``ToExpr] do
    let existing ← liftTermElabM do
      try
        let ty ← mkAppM cls #[mkConst name (info.levelParams.map Level.param)]
        discard <| synthInstance ty
        return true
      catch _ => return false
    unless existing do
      elabCommand (← `(deriving instance $(mkIdent cls):ident for $(mkIdent name):ident))
  modifyEnv fun env => derivedCodecTypes.addEntry env name
  return visited

private def prepareType (stx : Syntax) : CommandElabM Expr := do
  let ty ← liftTermElabM do
    let ty ← Term.elabType stx
    Term.synthesizeSyntheticMVarsNoPostponing
    instantiateMVars ty
  for name in ty.getUsedConstants do
    discard <| deriveCodecs name
  return ty

syntax (name := tdnData) (docComment)? "tdn_data " ident " : " term " from " str " [" str "]" : command

@[command_elab tdnData]
unsafe def elabData : CommandElab := fun original => do
  let stx := Syntax.node original.getHeadInfo `tdnData (original.getArgs.extract 1 original.getArgs.size)
  let name := (← getCurrNamespace) ++ stx[1].getId
  let ty ← prepareType stx[3]
  let path : System.FilePath := (stx[5].isStrLit?.getD "")
  let here := (System.FilePath.mk (← getFileName)).parent.getD "."
  let path := if path.isAbsolute then path else here / path
  let parsed ← match Json.parse (← IO.FS.readFile path) with
    | .ok j => pure j
    | .error e => throwError "invalid JSON: {e}"
  let value ← match parsed.getObjVal? (stx[7].isStrLit?.getD "") with
    | .ok j => pure j
    | .error e => throwError "missing evidence record: {e}"
  let typeStx : TSyntax `term := ⟨stx[3]⟩
  let jsonString := Syntax.mkStrLit value.compress
  let code ← `(match Lean.Json.parse $jsonString with
    | .error e => Except.error e
    | .ok json => match (Lean.fromJson? json : Except String $typeStx) with
      | .error e => Except.error e
      | .ok data => if Lean.toJson data == json then Except.ok (Lean.toExpr data)
                   else Except.error "noncanonical or unrecognized evidence fields")
  let decoded ← liftTermElabM do
    let e ← Term.elabTermEnsuringType code (mkApp2 (mkConst ``Except [Level.zero, Level.zero]) (mkConst ``String) (mkConst ``Expr))
    Term.synthesizeSyntheticMVarsNoPostponing
    let e ← instantiateMVars e
    evalExpr (Except String Expr) (mkApp2 (mkConst ``Except [Level.zero, Level.zero]) (mkConst ``String) (mkConst ``Expr)) e
  let value ← match decoded with
    | .ok v => pure v
    | .error e => throwError "cannot decode {path}: {e}"
  liftCoreM <| addAndCompile <| .defnDecl {
    name, levelParams := [], type := ty, value, hints := .regular 0, safety := .safe }
  addDeclarationRangesFromSyntax name original stx[1]
  liftTermElabM <| Term.addTermInfo' stx[1] (mkConst name) (isBinder := true)
  liftCoreM <| enableRealizationsForConst name
  addDocStringCore name s!"Imported from {path}, record {(stx[7].isStrLit?.getD "")}."

syntax (name := tdnExport) "tdn_export " ident " to " str " [" str "]" : command

@[command_elab tdnExport]
unsafe def elabExport : CommandElab := fun stx => do
  let name ← liftTermElabM <| resolveGlobalConstNoOverload stx[1]
  let ci ← getConstInfo name
  for dep in ci.type.getUsedConstants do
    discard <| deriveCodecs dep
  let term ← `(Lean.toJson $(mkIdent name))
  let json ← liftTermElabM do
    let e ← Term.elabTermEnsuringType term (mkConst ``Json)
    Term.synthesizeSyntheticMVarsNoPostponing
    evalExpr Json (mkConst ``Json) (← instantiateMVars e)
  let path : System.FilePath := (stx[3].isStrLit?.getD "")
  let previous ← if ← path.pathExists then
    match Json.parse (← IO.FS.readFile path) with
    | .ok j => pure j
    | .error e => throwError "{e}"
    else pure (Json.mkObj [])
  let object ← match previous.getObj? with
    | .ok o => pure o
    | .error e => throwError "{e}"
  let updated := Json.obj (object.insert (stx[5].isStrLit?.getD "") json)
  if let some parent := path.parent then IO.FS.createDirAll parent
  IO.FS.writeFile path (updated.pretty ++ "\n")
end TDN.Import
