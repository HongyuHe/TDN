namespace TDN.LinkProtection

/-- A controlled data port can protect and encrypt frames only with an installed transmit SA.
Control protocols bypassing the controlled data port are outside this operation. -/
structure Config where
  controlledPortEnabled : Bool
  protectFrames : Bool
  encryptFrames : Bool
  confidentialityOffset : Nat
  deriving DecidableEq, Repr

inductive WireFrame (Body : Type) where
  | plain (body : Body)
  | integrityOnly (association : Nat) (body : Body)
  | encrypted (association offset : Nat) (body : Body)
  deriving DecidableEq, Repr

/-- The body of an encrypted constructor is semantic plaintext, hidden on the physical wire
by the declared cryptographic implementation contract. No byte-level cipher is asserted here. -/
def transmit {Body : Type} (config : Config) (activeSA : Option Nat) (body : Body) :
    Option (WireFrame Body) :=
  if !config.controlledPortEnabled then none
  else if !config.protectFrames then some (.plain body)
  else match activeSA with
    | none => none
    | some association =>
      if config.encryptFrames then some (.encrypted association config.confidentialityOffset body)
      else some (.integrityOnly association body)

def FullyEncrypted {Body : Type} : WireFrame Body → Prop
  | .encrypted _ offset _ => offset = 0
  | _ => False

/-- Protect, encrypt and zero offset imply confidentiality for every emitted data frame,
including frames sent after the SA becomes unavailable. -/
theorem every_emitted_frame_is_encrypted {Body : Type} (config : Config)
    (protect : config.protectFrames = true) (encrypt : config.encryptFrames = true)
    (zero : config.confidentialityOffset = 0)
    (sa : Option Nat) (body : Body) (wire : WireFrame Body)
    (emitted : transmit config sa body = some wire) : FullyEncrypted wire := by
  cases enabled : config.controlledPortEnabled <;>
    cases sa <;> simp [transmit, enabled, protect, encrypt] at emitted
  obtain rfl := emitted
  exact zero

theorem absent_sa_blocks_data {Body : Type} (config : Config)
    (protect : config.protectFrames = true) (body : Body) :
    transmit config none body = none := by
  cases enabled : config.controlledPortEnabled <;> simp [transmit, enabled, protect]

theorem enabled_sa_emits_encryption {Body : Type} (config : Config)
    (enabled : config.controlledPortEnabled = true)
    (protect : config.protectFrames = true) (encrypt : config.encryptFrames = true)
    (association : Nat) (body : Body) :
    transmit config (some association) body =
      some (.encrypted association config.confidentialityOffset body) := by
  simp [transmit, enabled, protect, encrypt]

end TDN.LinkProtection
