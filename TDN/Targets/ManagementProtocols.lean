import TDN.Targets.CPDutyRecords

namespace TDN.Targets.Complete
open Compliance

def EncodeProtocolFields (fields : List String) : List UInt8 :=
  fields.flatMap (fun field =>
    let bytes := field.toUTF8.data.toList
    (toString bytes.length).toUTF8.data.toList ++ [58] ++ bytes)

structure MessageAuthenticationPrimitive where
  digest : String → List UInt8 → List UInt8
  verifyMAC : String → List UInt8 → List UInt8 → List UInt8 → Bool
  verifySignature : String → List UInt8 → List UInt8 → List UInt8 → Bool

inductive AuthenticatedTimeProtocol where
  | networkTimeSecurity | symmetricKeyNTP
  deriving DecidableEq

structure AuthenticatedTimeMessage where
  server : String
  client : String
  originateTime : Nat
  receiveTime : Nat
  transmitTime : Nat
  authenticatedBytes : List UInt8
  authenticationTag : List UInt8

structure AuthenticatedTimeConfiguration where
  server : String
  clients : List String
  protocol : AuthenticatedTimeProtocol
  algorithm : String
  key : List UInt8
  enabled : Bool
  reply : String → Nat → AuthenticatedTimeMessage
  accept : AuthenticatedTimeMessage → Bool

def AuthenticatedTimeConfiguration.Valid (configuration : AuthenticatedTimeConfiguration)
    (primitive : MessageAuthenticationPrimitive) (message : AuthenticatedTimeMessage) : Prop :=
  message.server = configuration.server ∧ message.client ∈ configuration.clients ∧
  message.authenticatedBytes = EncodeProtocolFields
    [message.server, message.client, toString message.originateTime,
      toString message.receiveTime, toString message.transmitTime] ∧
  message.authenticationTag ≠ [] ∧
  message.originateTime ≤ message.receiveTime ∧ message.receiveTime ≤ message.transmitTime ∧
  primitive.verifyMAC configuration.algorithm configuration.key
    message.authenticatedBytes message.authenticationTag = true

def AuthenticatedTimeConfiguration.Secure (configuration : AuthenticatedTimeConfiguration)
    (primitive : MessageAuthenticationPrimitive) : Prop :=
  configuration.enabled = true ∧ configuration.key ≠ [] ∧
  configuration.algorithm ∈ ["AES-SIV-CMAC-256", "HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512"] ∧
  (∀ client ∈ configuration.clients, ∀ time,
    (configuration.reply client time).originateTime = time ∧
    configuration.Valid primitive (configuration.reply client time)) ∧
  ∀ message, configuration.accept message = true → configuration.Valid primitive message

structure DNSQuestion where
  name : String
  recordType : Nat
  recordClass : Nat

structure DNSSECKey where
  owner : String
  publicKey : List UInt8
  algorithm : String
  keyTag : Nat
  flags : Nat
  protocol : Nat
  trustAnchor : Bool
  deriving DecidableEq

def DNSSECKey.canonical (key : DNSSECKey) : List UInt8 :=
  EncodeProtocolFields [key.owner, key.algorithm, toString key.keyTag,
    toString key.flags, toString key.protocol, toString key.publicKey]

structure DNSSECDelegation where
  child : String
  parent : String
  childKeyTag : Nat
  childAlgorithm : String
  digestAlgorithm : String
  digest : List UInt8
  signature : List UInt8
  inception : Nat
  expiration : Nat

def DNSSECDelegation.canonical (delegation : DNSSECDelegation) : List UInt8 :=
  EncodeProtocolFields [delegation.child, delegation.parent,
    toString delegation.childKeyTag, delegation.childAlgorithm, delegation.digestAlgorithm,
    toString delegation.digest, toString delegation.inception, toString delegation.expiration]

structure DNSResourceRecord where
  owner : String
  recordType : Nat
  recordClass : Nat
  ttl : Nat
  data : List UInt8

def DNSResourceRecord.canonical (record : DNSResourceRecord) : List UInt8 :=
  EncodeProtocolFields [record.owner, toString record.recordType, toString record.recordClass,
    toString record.ttl, toString record.data]

structure DNSSECResponse where
  question : DNSQuestion
  signer : String
  records : List DNSResourceRecord
  canonicalResourceRecords : List UInt8
  signature : List UInt8
  inception : Nat
  expiration : Nat

def DNSSECResponse.canonical (response : DNSSECResponse) : List UInt8 :=
  EncodeProtocolFields [response.signer, toString response.inception, toString response.expiration] ++
    response.records.flatMap DNSResourceRecord.canonical

structure DNSSECConfiguration where
  server : String
  names : List String
  keys : List DNSSECKey
  delegations : List DNSSECDelegation
  enabled : Bool
  response : DNSQuestion → Nat → Option DNSSECResponse
  accept : DNSSECResponse → Nat → Bool

def DNSSECConfiguration.Delegates (configuration : DNSSECConfiguration)
    (primitive : MessageAuthenticationPrimitive) (time : Nat)
    (parent child : DNSSECKey) : Prop :=
  parent ∈ configuration.keys ∧ child ∈ configuration.keys ∧
  child.protocol = 3 ∧ child.publicKey ≠ [] ∧
  ∃ delegation ∈ configuration.delegations,
    delegation.child = child.owner ∧ delegation.parent = parent.owner ∧
    delegation.childKeyTag = child.keyTag ∧ delegation.childAlgorithm = child.algorithm ∧
    delegation.digestAlgorithm ∈ ["SHA256", "SHA384"] ∧
    primitive.digest delegation.digestAlgorithm child.canonical = delegation.digest ∧
    delegation.inception ≤ time ∧ time < delegation.expiration ∧
    primitive.verifySignature parent.algorithm parent.publicKey
      delegation.canonical delegation.signature = true

def DNSSECConfiguration.TrustedKey (configuration : DNSSECConfiguration)
    (primitive : MessageAuthenticationPrimitive) (key : DNSSECKey) (time : Nat) : Prop :=
  key ∈ configuration.keys ∧ key.publicKey ≠ [] ∧ key.protocol = 3 ∧
  ∃ anchor ∈ configuration.keys, anchor.trustAnchor = true ∧
    Relation.ReflTransGen (configuration.Delegates primitive time) anchor key

def DNSSECConfiguration.Valid (configuration : DNSSECConfiguration)
    (primitive : MessageAuthenticationPrimitive) (message : DNSSECResponse) (time : Nat) : Prop :=
  message.records ≠ [] ∧ message.canonicalResourceRecords = message.canonical ∧
  (∀ record ∈ message.records, record.owner = message.question.name ∧
    record.recordType = message.question.recordType ∧
    record.recordClass = message.question.recordClass) ∧
  message.signature ≠ [] ∧ message.inception ≤ time ∧ time < message.expiration ∧
  ∃ key ∈ configuration.keys, key.owner = message.signer ∧
    configuration.TrustedKey primitive key time ∧
    primitive.verifySignature key.algorithm key.publicKey
      message.canonicalResourceRecords message.signature = true

def DNSSECConfiguration.Secure (configuration : DNSSECConfiguration)
    (primitive : MessageAuthenticationPrimitive) : Prop :=
  configuration.enabled = true ∧ configuration.keys ≠ [] ∧
  (∀ question time, question.name ∈ configuration.names →
    ∃ reply, configuration.response question time = some reply ∧
      reply.question.name = question.name ∧ reply.question.recordType = question.recordType ∧
      reply.question.recordClass = question.recordClass ∧ configuration.Valid primitive reply time) ∧
  ∀ message time, configuration.accept message time = true →
    configuration.Valid primitive message time

end TDN.Targets.Complete
