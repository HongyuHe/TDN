import TDN.Models.AclPermitLookupHints

open TDN TDN.LookupHints TDN.PacketPolicy

namespace AclLookupHintTests

def mask : AclFlowSelector :=
  { source := 10, destination := 20, protocol := "esp", ingress := "in", egress := "out",
    sourcePort := none, destinationPort := none, ipv4HeaderWords := none,
    matchedInboundPolicyIds := [], matchedOutboundPolicyIds := [],
    minimumBytes := 0, maximumBytes := 1400, requestFraming := false, replyFraming := false }

def denyLarge : PacketAclRule := ⟨[.networkBytesRange 1401 65535], .deny⟩
def permitOther : PacketAclRule := ⟨[.sourceRange 30 30], .allow⟩
def permitSelected : PacketAclRule := ⟨[.sourceRange 10 10, .destinationRange 20 20, .protocol "esp"], .allow⟩
def index : AclRuleIndex := ⟨[denyLarge], .branch (.leaf permitOther) (.leaf permitSelected)⟩
def hint : AclPermitLookupHint := ⟨[true], [0]⟩

example : index.Valid := by native_decide
example : checkAclPermit index mask hint = true := by native_decide
example : checkAclPermit index mask { hint with ruleIndex := [false] } = false := by native_decide
example : checkAclPermit index mask { hint with ruleIndex := [true, false] } = false := by native_decide
example : checkAclPermit index mask { hint with rejectedAtoms := [] } = false := by native_decide
example : checkAclPermit index mask { hint with rejectedAtoms := [1] } = false := by native_decide
example : checkAclPermit index { mask with maximumBytes := 1401 } hint = false := by native_decide
example : checkAclPermit index { mask with source := 11 } hint = false := by native_decide
example : checkAclPermit { index with earlierRules := [⟨[.protocol "esp"], .deny⟩] } mask hint = false := by native_decide
example : ¬ ({ index with allowed := .branch (.leaf { permitOther with verdict := .deny }) (.leaf permitSelected) } : AclRuleIndex).Valid := by native_decide

example : mask.IsPermittedByAclChain index.rules :=
  checked_acl_hint_proves_permit index (by native_decide) mask hint (by native_decide)

example : ¬ mask.IsPermittedByAclChain (⟨[.protocol "esp"], .deny⟩ :: index.rules) := by native_decide

end AclLookupHintTests
