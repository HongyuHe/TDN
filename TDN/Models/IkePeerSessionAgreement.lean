import Mathlib.Data.List.Basic

namespace TDN.IKEContexts

structure Endpoint where
  device : Nat
  localIdentity : String
  remoteIdentity : String
  localAddress : Nat
  remoteAddress : Nat
  ikeInitiatorSPI : Nat
  ikeResponderSPI : Nat
  inboundSPI : Nat
  outboundSPI : Nat
  localLow : Nat
  localHigh : Nat
  remoteLow : Nat
  remoteHigh : Nat
  localIsInitiator : Bool
  childHasPfs : Bool
  deriving DecidableEq, Repr

def Peer (sender receiver : Endpoint) : Prop :=
  sender.localIdentity = receiver.remoteIdentity ∧
  sender.remoteIdentity = receiver.localIdentity ∧
  sender.localAddress = receiver.remoteAddress ∧
  sender.remoteAddress = receiver.localAddress ∧
  sender.ikeInitiatorSPI = receiver.ikeInitiatorSPI ∧
  sender.ikeResponderSPI = receiver.ikeResponderSPI ∧
  sender.outboundSPI = receiver.inboundSPI ∧
  sender.inboundSPI = receiver.outboundSPI ∧
  sender.localLow = receiver.remoteLow ∧ sender.localHigh = receiver.remoteHigh ∧
  sender.remoteLow = receiver.localLow ∧ sender.remoteHigh = receiver.localHigh ∧
  sender.localIsInitiator = !receiver.localIsInitiator ∧ sender.childHasPfs = receiver.childHasPfs

instance (sender receiver : Endpoint) : Decidable (Peer sender receiver) := by
  unfold Peer
  infer_instance

def sendName (endpoint : Endpoint) : List Nat :=
  [endpoint.ikeInitiatorSPI, endpoint.ikeResponderSPI, endpoint.localAddress,
   endpoint.remoteAddress, endpoint.outboundSPI, endpoint.inboundSPI]

def receiveName (endpoint : Endpoint) : List Nat :=
  [endpoint.ikeInitiatorSPI, endpoint.ikeResponderSPI, endpoint.remoteAddress,
   endpoint.localAddress, endpoint.inboundSPI, endpoint.outboundSPI]

theorem reciprocal_peers_agree_on_directional_record (sender receiver : Endpoint)
    (checked : Peer sender receiver) : sendName sender = receiveName receiver := by
  rcases checked with ⟨_, _, addresses, remote, initiator, responder, outbound, inbound, _⟩
  simp only [sendName, receiveName, addresses, remote, initiator, responder, outbound, inbound]

theorem reciprocal_peers_share_key_under_derivation_contract
    {Secret : Type} (sender receiver : Endpoint)
    (sendKey receiveKey : Endpoint → Secret)
    (derivation : ∀ a b, Peer a b → sendKey a = receiveKey b)
    (checked : Peer sender receiver) : sendKey sender = receiveKey receiver :=
  derivation sender receiver checked

end TDN.IKEContexts
