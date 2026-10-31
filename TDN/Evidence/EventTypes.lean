import Mathlib.Data.List.Basic

namespace TDN.Evidence

structure IKEExchangeObservation where
  initRequestLine : Nat
  initResponseLine : Nat
  intermediateRequestLine : Nat
  intermediateResponseLine : Nat
  authRequestLine : Nat
  authResponseLine : Nat
  initialKeyExchange : String
  additionalKeyExchange : String
  signatureAlgorithms : List String
  espCipher : String
  initMessageBytes : List Nat
  intermediateRequestFragments : Nat
  intermediateResponseFragments : Nat
  authRequestFragments : Nat
  authResponseFragments : Nat
  initialIkeVersion : Nat
  usefulReplies : Nat
  deriving DecidableEq, Repr

def ObservedObjectiveSequence (e : IKEExchangeObservation) : Prop :=
  e.initRequestLine < e.initResponseLine ∧
  e.initResponseLine < e.intermediateRequestLine ∧
  e.intermediateRequestLine < e.intermediateResponseLine ∧
  e.intermediateResponseLine < e.authRequestLine ∧
  e.authRequestLine < e.authResponseLine ∧
  e.initialKeyExchange = "ECP_384" ∧ e.additionalKeyExchange = "ML_KEM_1024" ∧
  e.signatureAlgorithms.length = 2 ∧ (∀ a ∈ e.signatureAlgorithms, a = "ML_DSA_87") ∧
  e.espCipher = "AES_GCM_16_256" ∧ e.initialIkeVersion = 2 ∧
  1 < e.intermediateRequestFragments ∧ 1 < e.intermediateResponseFragments ∧
  1 < e.authRequestFragments ∧ 1 < e.authResponseFragments ∧ 0 < e.usefulReplies

structure MKAPeerObservation where
  peer : String
  secured : Bool
  livePeers : Nat
  helloMs : Nat
  activeTxSAs : Nat
  activeRxSAs : Nat
  cipher : String
  icvRejections : Nat
  deriving DecidableEq, Repr

structure MKAExperiment where
  declaredMatchingCAKs : Bool
  peers : List MKAPeerObservation
  transmitted : Nat
  received : Nat
  deriving DecidableEq, Repr

def ObservedMatchingMKASuccess (e : MKAExperiment) : Prop :=
  e.declaredMatchingCAKs = true ∧ e.peers.length = 2 ∧
  (∀ p ∈ e.peers, p.secured = true ∧ 0 < p.livePeers ∧
    0 < p.activeTxSAs ∧ 0 < p.activeRxSAs ∧ p.cipher = "GCM-AES-256") ∧
  0 < e.transmitted ∧ e.received = e.transmitted

def ObservedMismatchedMKARefusal (e : MKAExperiment) : Prop :=
  e.declaredMatchingCAKs = false ∧ e.peers.length = 2 ∧
  (∀ p ∈ e.peers, p.secured = false ∧ p.livePeers = 0 ∧
    p.activeTxSAs = 0 ∧ p.activeRxSAs = 0 ∧ 0 < p.icvRejections) ∧
  0 < e.transmitted ∧ e.received = 0

structure IKEHeaderObservation where
  source : String
  destination : String
  ipTotalLength : Nat
  moreFragments : Bool
  fragmentOffsetBytes : Nat
  exchangeType : Nat
  messageId : Nat
  nextPayload : Nat
  fragmentNumber : Nat
  fragmentTotal : Nat
  deriving DecidableEq, Repr

def RecordedHeadersFitWithoutIPFragmentation (headers : List IKEHeaderObservation) (mtu : Nat) : Prop :=
  headers ≠ [] ∧ 0 < mtu ∧ ∀ h ∈ headers,
    h.ipTotalLength ≤ mtu ∧ h.moreFragments = false ∧ h.fragmentOffsetBytes = 0

def RecordedExchangeMessageKinds (headers : List IKEHeaderObservation) : Prop :=
  ∀ h ∈ headers,
    (h.exchangeType = 34 ∧ h.messageId = 0 ∧ h.nextPayload = 33) ∨
    (h.exchangeType = 43 ∧ h.messageId = 1 ∧ h.nextPayload = 53 ∧ 0 < h.fragmentNumber ∧ h.fragmentNumber ≤ h.fragmentTotal) ∨
    (h.exchangeType = 35 ∧ h.messageId = 2 ∧ h.nextPayload = 53 ∧ 0 < h.fragmentNumber ∧ h.fragmentNumber ≤ h.fragmentTotal)

end TDN.Evidence
