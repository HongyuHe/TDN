import TDN.Semantics.Filter

namespace TDN.PacketPolicy

structure Packet where
  source : Nat
  destination : Nat
  protocol : String
  ingress : String
  egress : String
  sourcePort : Nat
  destinationPort : Nat
  ipv4HeaderWords : Nat
  inboundPolicies : List Nat
  outboundPolicies : List Nat
  connectionState : String
  ipv6NextHeader : Nat := 0
  icmpType : Nat := 0
  icmpCode : Nat := 0
  hopLimit : Nat := 0
  etherType : Option Nat := none
  payloadBytes : Option (List UInt8) := none
  connectionId : Option String := none
  networkBytes : Option Nat := none
  ipv4FragmentOffset : Option Nat := none
  deriving DecidableEq

def IKEHeader (bytes : List UInt8) : Prop :=
  28 ≤ bytes.length ∧
  (bytes[17]?.getD 0).toNat / 16 = 2 ∧
  (bytes[24]?.getD 0).toNat * 16777216 + (bytes[25]?.getD 0).toNat * 65536 +
    (bytes[26]?.getD 0).toNat * 256 + (bytes[27]?.getD 0).toNat = bytes.length

instance (bytes : List UInt8) : Decidable (IKEHeader bytes) := by
  unfold IKEHeader
  infer_instance

def Packet.IPv4FragmentOffsetDecoded (packet : Packet) (header : List UInt8) : Prop :=
  8 ≤ header.length ∧
  packet.ipv4FragmentOffset = some
    (((header[6]?.getD 0).toNat * 256 + (header[7]?.getD 0).toNat) % 8192)

def Packet.IPsecUDPFraming (packet : Packet) : Prop :=
  packet.source < 2^32 ∧ packet.destination < 2^32 ∧
  packet.ipv4HeaderWords = 5 ∧ packet.ipv4FragmentOffset = some 0 ∧
  packet.protocol = "udp" ∧
  ∃ bytes, packet.payloadBytes = some bytes ∧
    packet.networkBytes = some (28 + bytes.length) ∧
    ((packet.destinationPort = 500 ∧ IKEHeader bytes) ∨
      (packet.destinationPort = 4500 ∧ 8 ≤ bytes.length ∧
        (bytes.take 4 ≠ [0, 0, 0, 0] ∨
          bytes.take 4 = [0, 0, 0, 0] ∧ IKEHeader (bytes.drop 4))))

instance (packet : Packet) : Decidable packet.IPsecUDPFraming := by
  unfold Packet.IPsecUDPFraming
  infer_instance

def Packet.IPsecUDPFramingWithOptions (packet : Packet) : Prop :=
  packet.source < 2^32 ∧ packet.destination < 2^32 ∧
  5 ≤ packet.ipv4HeaderWords ∧ packet.ipv4HeaderWords ≤ 15 ∧
  packet.ipv4FragmentOffset = some 0 ∧ packet.protocol = "udp" ∧
  ∃ bytes, packet.payloadBytes = some bytes ∧
    packet.networkBytes = some (4 * packet.ipv4HeaderWords + 8 + bytes.length) ∧
    ((packet.destinationPort = 500 ∧ IKEHeader bytes) ∨
      (packet.destinationPort = 4500 ∧ 8 ≤ bytes.length ∧
        (bytes.take 4 ≠ [0, 0, 0, 0] ∨
          bytes.take 4 = [0, 0, 0, 0] ∧ IKEHeader (bytes.drop 4))))

instance (packet : Packet) : Decidable packet.IPsecUDPFramingWithOptions := by
  unfold Packet.IPsecUDPFramingWithOptions
  infer_instance


def Packet.IPsecUDPReplyFramingWithOptions (packet : Packet) : Prop :=
  ({ packet with
    sourcePort := packet.destinationPort
    destinationPort := packet.sourcePort } : Packet).IPsecUDPFramingWithOptions

instance (packet : Packet) : Decidable packet.IPsecUDPReplyFramingWithOptions := by
  unfold Packet.IPsecUDPReplyFramingWithOptions
  infer_instance


def byteField (bytes : List UInt8) (offset count : Nat) : Nat :=
  ((bytes.drop offset).take count).foldl (fun value byte => value * 256 + byte.toNat) 0

def Packet.MKAFraming (packet : Packet) (actorSCI : Nat) : Prop :=
  packet.protocol = "ethernet" ∧ packet.etherType = some 34958 ∧
  packet.source = actorSCI / 65536 ∧
  ∃ bytes, packet.payloadBytes = some bytes ∧ 36 ≤ bytes.length ∧
    bytes[1]? = some 5 ∧ byteField bytes 2 2 = bytes.length - 4 ∧
    byteField bytes 8 8 = actorSCI

instance (packet : Packet) (actorSCI : Nat) : Decidable (packet.MKAFraming actorSCI) := by
  unfold Packet.MKAFraming
  infer_instance

inductive Atom where
  | sourceRange (low high : Nat)
  | destinationRange (low high : Nat)
  | protocol (name : String)
  | ingress (name : String)
  | egress (name : String)
  | sourcePorts (ports : List Nat)
  | destinationPorts (ports : List Nat)
  | ipv4HeaderWords (words : Nat)
  | ipv6NextHeaders (values : List Nat)
  | icmpType (value : Nat)
  | icmpCode (value : Nat)
  | hopLimit (value : Nat)
  | etherTypes (values : List Nat)
  | connectionId (value : String)
  | networkBytesRange (low high : Nat)
  | ipsecUDPFraming
  | ipsecUDPFramingWithOptions
  | ipsecUDPReplyFramingWithOptions
  | mkaFraming (actorSCI : Nat)
  | ethernetHeaderBytes (bytes : Nat)
  | payloadBytesRange (low high : Nat)
  | payloadByteEquals (offset : Nat) (value : UInt8)
  | inboundPolicy (requestId : Nat)
  | outboundPolicy (requestId : Nat)
  | connectionStates (states : List String)
  deriving DecidableEq, Repr

def Atom.holds : Atom → Packet → Prop
  | .sourceRange low high, p => low ≤ p.source ∧ p.source ≤ high
  | .destinationRange low high, p => low ≤ p.destination ∧ p.destination ≤ high
  | .protocol name, p => p.protocol = name
  | .ingress name, p => p.ingress = name
  | .egress name, p => p.egress = name
  | .sourcePorts ports, p => p.sourcePort ∈ ports
  | .destinationPorts ports, p => p.destinationPort ∈ ports
  | .ipv4HeaderWords words, p => p.ipv4HeaderWords = words
  | .ipv6NextHeaders values, p => p.ipv6NextHeader ∈ values
  | .icmpType value, p => p.icmpType = value
  | .icmpCode value, p => p.icmpCode = value
  | .hopLimit value, p => p.hopLimit = value
  | .etherTypes values, p => ∃ value, p.etherType = some value ∧ value ∈ values
  | .connectionId value, p => p.connectionId = some value
  | .networkBytesRange low high, p => ∃ bytes, p.networkBytes = some bytes ∧ low ≤ bytes ∧ bytes ≤ high
  | .ipsecUDPFraming, p => p.IPsecUDPFraming
  | .ipsecUDPFramingWithOptions, p => p.IPsecUDPFramingWithOptions
  | .ipsecUDPReplyFramingWithOptions, p => p.IPsecUDPReplyFramingWithOptions
  | .mkaFraming actorSCI, p => p.MKAFraming actorSCI
  | .ethernetHeaderBytes bytes, p => p.protocol = "ethernet" ∧
      ∃ payload, p.payloadBytes = some payload ∧ p.networkBytes = some (bytes + payload.length)
  | .payloadBytesRange low high, p =>
      ∃ bytes, p.payloadBytes = some bytes ∧ low ≤ bytes.length ∧ bytes.length ≤ high
  | .payloadByteEquals offset value, p =>
      (p.payloadBytes.bind (fun bytes => bytes[offset]?)) = some value
  | .inboundPolicy id, p => id ∈ p.inboundPolicies
  | .outboundPolicy id, p => id ∈ p.outboundPolicies
  | .connectionStates states, p => p.connectionState ∈ states

instance (a : Atom) (p : Packet) : Decidable (a.holds p) := by
  cases a <;> unfold Atom.holds <;> infer_instance

structure Rule where
  atoms : List Atom
  verdict : Filter.Verdict
  deriving DecidableEq, Repr

def Rule.toFilter (r : Rule) : Filter.Rule Packet :=
  ⟨fun p => r.atoms.all (fun a => decide (a.holds p)), r.verdict⟩

lemma matching_atom {r : Rule} {p : Packet}
    (matched : r.toFilter.accepts p = true) {a : Atom} (member : a ∈ r.atoms) :
    a.holds p := by
  have all := List.all_eq_true.mp matched
  exact of_decide_eq_true (all a member)

def OutboundGuard (r : Rule) (inside outside : String) : Prop :=
  .ingress inside ∈ r.atoms ∧ .egress outside ∈ r.atoms ∧
  ∃ a ∈ r.atoms, match a with | .outboundPolicy _ => True | _ => False

def InboundGuard (r : Rule) (inside outside : String) : Prop :=
  .ingress outside ∈ r.atoms ∧ .egress inside ∈ r.atoms ∧
  ∃ a ∈ r.atoms, match a with | .inboundPolicy _ => True | _ => False

def Guarded (r : Rule) (inside outside : String) : Prop :=
  OutboundGuard r inside outside ∨ InboundGuard r inside outside

instance (r : Rule) (inside outside : String) : Decidable (Guarded r inside outside) := by
  unfold Guarded OutboundGuard InboundGuard
  letI dout (a : Atom) : Decidable (match a with | .outboundPolicy _ => True | _ => False) := by
    cases a <;> infer_instance
  letI din (a : Atom) : Decidable (match a with | .inboundPolicy _ => True | _ => False) := by
    cases a <;> infer_instance
  infer_instance

def ProtectedForward (inside outside : String) (p : Packet) : Prop :=
  (p.ingress = inside ∧ p.egress = outside ∧ ∃ id, id ∈ p.outboundPolicies) ∨
  (p.ingress = outside ∧ p.egress = inside ∧ ∃ id, id ∈ p.inboundPolicies)

lemma guarded_rule_protects {r : Rule} {inside outside : String} {p : Packet}
    (guard : Guarded r inside outside) (matched : r.toFilter.accepts p = true) :
    ProtectedForward inside outside p := by
  rcases guard with ⟨hin, hout, a, ha, hkind⟩ | ⟨hin, hout, a, ha, hkind⟩
  · have pi : p.ingress = inside := matching_atom matched hin
    have po : p.egress = outside := matching_atom matched hout
    have policyEvidence := matching_atom matched ha
    cases a <;> simp only at hkind <;> try contradiction
    exact Or.inl ⟨pi, po, _, policyEvidence⟩
  · have pi : p.ingress = outside := matching_atom matched hin
    have po : p.egress = inside := matching_atom matched hout
    have policyEvidence := matching_atom matched ha
    cases a <;> simp only at hkind <;> try contradiction
    exact Or.inr ⟨pi, po, _, policyEvidence⟩

theorem forwarding_policy_protects (rules : List Rule) (inside outside : String)
    (checked : ∀ r ∈ rules, r.verdict = .allow → Guarded r inside outside)
    (p : Packet) (accepted : Filter.evaluate (rules.map Rule.toFilter) .deny p = .allow) :
    ProtectedForward inside outside p := by
  apply Filter.default_deny_sound (rules.map Rule.toFilter) (ProtectedForward inside outside) ?_ p accepted
  intro r hr allow packet matched
  obtain ⟨source, hsource, rfl⟩ := List.mem_map.mp hr
  exact guarded_rule_protects (checked source hsource allow) matched

end TDN.PacketPolicy
