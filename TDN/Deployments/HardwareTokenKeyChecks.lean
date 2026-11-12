import TDN.Import.SnapshotLoader
import TDN.Requirements.VerifiedPrivateKeyConfinement

namespace TDN.Deployments.HardwareTokenKeyChecks

structure TokenKeyRecord where
  device : String
  backend : String
  tokenSerial : String
  keyIdHex : String
  publicSPKI : String
  generated : Bool
  sensitive : Bool
  alwaysSensitive : Bool
  extractable : Bool
  neverExtractable : Bool
  copyable : Bool
  modifiable : Bool
  decrypt : Bool
  derive : Bool
  sign : Bool
  unwrap : Bool
  «local» : Bool
  privateKeyCountBefore : Nat
  privateKeyCountAfter : Nat
  attributesUnchanged : Bool
  certificateSPKIMatches : Bool
  signatureVerified : Bool
  attempts : List (String × Nat)
  observationIds : List String
  deriving DecidableEq, Repr

load_network_records records : List TokenKeyRecord from "../../data/evidence/proof001-token-key-boundary/token-observations-v001.json" ["tokenKeys"]

def objects : List Requirements.Msc.KeyObject :=
  records.mapIdx (fun index record =>
    ⟨index, (record.device, record.publicSPKI), record.sensitive, record.extractable⟩)

lemma complete_two_key_inventory :
    records.length = 2 ∧
      ∀ record ∈ records, record.privateKeyCountBefore = 1 ∧
        record.privateKeyCountAfter = 1 ∧ record.attributesUnchanged = true ∧
        record.generated = true ∧ record.«local» = true ∧
        record.certificateSPKIMatches = true ∧ record.observationIds ≠ [] := by native_decide

lemma checked_protected_attributes :
    ∀ record ∈ records,
      record.sensitive = true ∧ record.alwaysSensitive = true ∧
      record.extractable = false ∧ record.neverExtractable = true ∧
      record.copyable = false ∧ record.modifiable = false ∧
      record.decrypt = false ∧ record.derive = false ∧
      record.sign = true ∧ record.unwrap = false := by native_decide

lemma checked_actual_operation_results :
    ∀ record ∈ records, record.signatureVerified = true ∧
      ("read-private-value", 17) ∈ record.attempts ∧
      ("make-extractable", 27) ∈ record.attempts ∧
      ("make-nonsensitive", 27) ∈ record.attempts ∧
      ("copy-private-key", 27) ∈ record.attempts ∧
      ("wrap-private-key", 106) ∈ record.attempts ∧
      ("wrong-pin-login", 160) ∈ record.attempts := by native_decide

lemma initial_objects_restricted :
    ∀ object ∈ objects, object.Restricted := by
  unfold objects KeyInterface.Object.Restricted
  native_decide
lemma initial_store_safe (confidential : Requirements.Msc.GatewayKey → Prop) :
    KeyInterface.StoreSafe confidential objects := by
  intro object member _
  exact initial_objects_restricted object member

end TDN.Deployments.HardwareTokenKeyChecks
