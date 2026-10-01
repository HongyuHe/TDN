import Std

/-!
# Vocabulary shared by the snapshot and the proofs

Lean `structure` declarations below are records. Each field is data, not a proof
that the corresponding fact holds on Linux. The offline importer validates a
Twinet export and writes records of these types into `Deployment.lean`. Lean
then checks propositions about those records. The importer, the observations,
and the interpretation of Linux behavior remain explicit trust boundaries.

Security levels are complete, unordered labels. We never assume S2 dominates
S1. Device names and addresses retain the spellings in the deployed manifest.
-/
namespace TDN.MSC

inductive SecurityLevel where
  | s1 | s2
  deriving DecidableEq, BEq, Repr

inductive Site where
  | a | b
  deriving DecidableEq, BEq, Repr

inductive Role where
  | transport | firewall | grayFirewall | host | inner | outer | switch | admin
  deriving DecidableEq, BEq, Repr

inductive Zone where
  | red | gray | black | management
  deriving DecidableEq, BEq, Repr

/-- An address is kept as text here; packet filtering uses numeric IPv4 below. -/
structure Interface where
  name : String
  zone : Zone
  address : String
  deriving DecidableEq, BEq, Repr

structure Route where
  network : String
  via : String
  deriving DecidableEq, BEq, Repr

/-- `managementDomain` identifies a management cable component's IPv4 subnet.
Explicit full-export import derives it from addressed interfaces and rejects
inconsistent subnets. Required import removes management ports and leaves this
field absent. A management domain is not a clearance. -/
structure Device where
  id : String
  role : Role
  site : Option Site
  level : Option SecurityLevel
  interfaces : List Interface
  routes : List Route
  managementDomain : Option String
  admin : Option String
  deriving DecidableEq, BEq, Repr

/-- A cable records both named endpoints. `zone` agrees with both interfaces;
the importer checks that agreement before producing Lean declarations. -/
structure Link where
  a : String
  aPort : String
  b : String
  bPort : String
  zone : Zone
  deriving DecidableEq, BEq, Repr

structure Tunnel where
  owner : String
  peer : String
  localAddress : String
  remoteAddress : String
  localSelector : String
  remoteSelector : String
  trust : String
  reqid : Nat
  deriving DecidableEq, BEq, Repr

/-- These settings come from each hashed `intended.swanctl.conf`, not from
daemon memory. Keeping them separate from `Tunnel` lets Lean check agreement
between the topology declaration and the independently parsed intended file.
Times are integer seconds. Proposal strings are explicit lists with no daemon
defaults inferred. A theorem about these records is a configuration theorem. -/
structure CryptoConfig where
  device : String
  version : Nat
  localAddress : String
  remoteAddress : String
  localSelector : String
  remoteSelector : String
  reqid : Nat
  mode : String
  ikeProposal : String
  espProposal : String
  reauthSeconds : Nat
  ikeRekeySeconds : Nat
  overSeconds : Nat
  childLifeSeconds : Nat
  localAuth : String
  remoteAuth : String
  localIdentity : String
  remoteIdentity : String
  localCertificate : String
  remoteCA : String
  revocation : String
  deriving DecidableEq, BEq, Repr

/-- Public fields reported by the sampled certificate-list command. Identifiers
are reported strings, not independently recomputed fingerprints. The Boolean
records the command's "has private key" indicator without importing key bytes.
No signature, validity-period, revocation, or private-key independence claim is
encoded in these fields. -/
structure PublicCertificate where
  subject : String
  issuer : String
  serial : String
  subjectKeyId : String
  authorityKeyId : String
  keyId : String
  altNames : List String
  isCA : Bool
  hasPrivateKey : Bool
  deriving DecidableEq, BEq, Repr

/-- Missing or failed certificate observations remain `none`. Each inventory
keeps the device and observation time from the same sampled status record. -/
structure CertificateInventory where
  device : String
  observedAt : String
  certificates : Option (List PublicCertificate)
  deriving DecidableEq, BEq, Repr

/-- IPv4 addresses are unsigned 32-bit values. A prefix length is generated
from a validated IPv4 CIDR, so the snapshot contains only lengths 0 through 32. -/
structure Prefix where
  address : UInt32
  length : Nat
  deriving DecidableEq, BEq, Repr

def Prefix.contains (cidr : Prefix) (address : UInt32) : Bool :=
  address.toNat / 2 ^ (32 - cidr.length) ==
    cidr.address.toNat / 2 ^ (32 - cidr.length)

/-- Parse a concrete IPv4 address inside Lean, so policy contracts can derive
addresses from tunnel declarations independently of the Python rule parser.
Malformed or out-of-range values return `none`; no truncation is accepted. -/
def splitChars (separator : Char) (value : List Char) : List (List Char) :=
  value.foldr (fun c parts =>
    if c = separator then [] :: parts
    else match parts with
      | [] => [[c]]
      | first :: rest => (c :: first) :: rest) [[]]

def decimalChars? (value : List Char) : Option Nat :=
  if value.isEmpty then none else
    value.foldlM (fun n c =>
      if 48 ≤ c.toNat ∧ c.toNat ≤ 57 then some (10 * n + c.toNat - 48) else none) 0

def ipv4Chars? (value : List Char) : Option UInt32 :=
  match splitChars '.' value with
  | [a, b, c, d] => do
    let a ← decimalChars? a
    let b ← decimalChars? b
    let c ← decimalChars? c
    let d ← decimalChars? d
    if a < 256 ∧ b < 256 ∧ c < 256 ∧ d < 256 then
      some (UInt32.ofNat (a * 16777216 + b * 65536 + c * 256 + d))
    else none
  | _ => none

def ipv4? (value : String) : Option UInt32 := ipv4Chars? value.toList

/-- A tunnel selector must explicitly include its IPv4 prefix length. -/
def Prefix.parse? (value : String) : Option Prefix :=
  match splitChars '/' value.toList with
  | [address, length] => do
    let address ← ipv4Chars? address
    let length ← decimalChars? length
    if length ≤ 32 then some ⟨address, length⟩ else none
  | _ => none

/-- The fields visible to the modeled FORWARD chain. Policy IDs mean the kernel
reports a tunnel-mode XFRM policy in that direction. An inbound ID additionally
represents the kernel's IPsec processing history. They are not packet-supplied
flags. SA availability is checked separately by the symbolic encryption model. -/
structure RoutedPacket where
  input : String
  output : String
  source : UInt32
  destination : UInt32
  protocol : Nat
  /-- IPv4 header length in 32-bit words; five means no IP options. -/
  headerWords : Nat := 5
  destinationPort : Nat := 0
  inPolicy : Option Nat := none
  outPolicy : Option Nat := none
  deriving Repr

/-- A supported ACCEPT rule from an exported FORWARD chain. `none` means a
field is unrestricted. Empty destinationPorts means no port restriction.
The importer rejects unsupported forwarding syntax instead of dropping it. -/
structure ForwardRule where
  input : Option String := none
  output : Option String := none
  source : Option Prefix := none
  destination : Option Prefix := none
  protocol : Option Nat := none
  destinationPorts : List Nat := []
  inPolicy : Option Nat := none
  outPolicy : Option Nat := none
  /-- Exact supported u32 header-length guard, rather than arbitrary u32 code. -/
  noOptions : Bool := false
  deriving DecidableEq, BEq, Repr

structure ForwardTable where
  device : String
  defaultAccept : Bool
  rules : List ForwardRule
  deriving DecidableEq, BEq, Repr

/-- An observation is a sampled statement, not a continuously true invariant.
`none` for `tunnelEstablished` means no usable tunnel observation was available;
it never means that encryption was proven absent or safe. -/
structure DeviceObservation where
  device : String
  observedAt : String
  running : Bool
  deployedSpecHash : String
  errors : List String
  tunnelEstablished : Option Bool
  deriving DecidableEq, BEq, Repr

end TDN.MSC
