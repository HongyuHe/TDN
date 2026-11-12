import TDN.Models.AclPermitCertificates

open TDN TDN.Certificates TDN.PacketPolicy

namespace AclCertificateTests

def mask : AclFlowSelector :=
  { source := 10, destination := 20, protocol := "esp", ingress := "in", egress := "out",
    sourcePort := none, destinationPort := none, ipv4HeaderWords := none,
    matchedInboundPolicyIds := [], matchedOutboundPolicyIds := [],
    minimumBytes := 0, maximumBytes := 1400, requestFraming := false, replyFraming := false }

def denyLarge : Rule := ⟨[.networkBytesRange 1401 65535], .deny⟩
def permitOther : Rule := ⟨[.sourceRange 30 30], .allow⟩
def permitSelected : Rule := ⟨[.sourceRange 10 10, .destinationRange 20 20, .protocol "esp"], .allow⟩
def index : AclRuleIndex := ⟨[denyLarge], .branch (.leaf permitOther) (.leaf permitSelected)⟩
def witness : AclPermitWitness := ⟨[true], [0]⟩

example : index.Valid := by decide
example : checkAclPermit index mask witness = true := by decide
example : checkAclPermit index mask { witness with ruleIndex := [false] } = false := by decide
example : checkAclPermit index mask { witness with ruleIndex := [true, false] } = false := by decide
example : checkAclPermit index mask { witness with rejectedAtoms := [] } = false := by decide
example : checkAclPermit index mask { witness with rejectedAtoms := [1] } = false := by decide
example : checkAclPermit index { mask with maximumBytes := 1401 } witness = false := by decide
example : checkAclPermit index { mask with source := 11 } witness = false := by decide
example : checkAclPermit { index with earlierRules := [⟨[.protocol "esp"], .deny⟩] } mask witness = false := by decide
example : ¬ ({ index with allowed := .branch (.leaf { permitOther with verdict := .deny }) (.leaf permitSelected) } : AclRuleIndex).Valid := by decide

example : mask.IsPermittedByAclChain index.rules :=
  table_driven_acl_certificate_sound index (by decide) mask witness (by decide)

example : ¬ mask.IsPermittedByAclChain (⟨[.protocol "esp"], .deny⟩ :: index.rules) := by decide

end AclCertificateTests
