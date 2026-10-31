import TDN.Semantics.Filter
namespace TDN.BridgePolicy

structure Frame where
  etherType : Nat
  ipProtocol : Nat
  source : Nat
  destination : Nat
  sourcePort : Nat
  destinationPort : Nat

def HTTPRequest (client server : Nat) (p : Frame) : Prop :=
  p.source = client ∧ p.destination = server ∧ p.destinationPort = 80

def HTTPResponse (client server : Nat) (p : Frame) : Prop :=
  p.source = server ∧ p.destination = client ∧ p.sourcePort = 80

instance (client server : Nat) (p : Frame) : Decidable (HTTPRequest client server p) :=
  inferInstanceAs (Decidable (_ ∧ _ ∧ _))
instance (client server : Nat) (p : Frame) : Decidable (HTTPResponse client server p) :=
  inferInstanceAs (Decidable (_ ∧ _ ∧ _))

def chain (client server : Nat) : List (Filter.Rule Frame) :=
  [⟨fun p => decide (p.etherType = 2054), .allow⟩,
   ⟨fun p => decide (p.etherType = 2048 ∧ p.ipProtocol = 50), .allow⟩,
   ⟨fun p => decide (p.etherType = 2048 ∧ p.ipProtocol = 6 ∧ HTTPRequest client server p), .allow⟩,
   ⟨fun p => decide (p.etherType = 2048 ∧ p.ipProtocol = 6 ∧ HTTPResponse client server p), .allow⟩]

/-- Every accepted IPv4 TCP frame matches the directed HTTP exception. ARP and ESP
remain distinct admitted cases. Actual bridge-hook correspondence is external. -/
theorem accepted_tcp_is_bounded (client server : Nat) (p : Frame)
    (ipv4 : p.etherType = 2048) (tcp : p.ipProtocol = 6)
    (accepted : Filter.evaluate (chain client server) .deny p = .allow) :
    HTTPRequest client server p ∨ HTTPResponse client server p := by
  by_cases request : HTTPRequest client server p
  · exact Or.inl request
  by_cases response : HTTPResponse client server p
  · exact Or.inr response
  simp [chain, Filter.evaluate, ipv4, tcp, request, response] at accepted

theorem has_useful_request (client server : Nat) :
    ∃ p, p.etherType = 2048 ∧ p.ipProtocol = 6 ∧ HTTPRequest client server p ∧
      Filter.evaluate (chain client server) .deny p = .allow := by
  refine ⟨⟨2048, 6, client, server, 49152, 80⟩, rfl, rfl, ?_, ?_⟩
  · simp [HTTPRequest]
  · simp [chain, Filter.evaluate, HTTPRequest]
end TDN.BridgePolicy
