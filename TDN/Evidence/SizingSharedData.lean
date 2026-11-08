import TDN.Evidence.PacketSizingRecords

namespace TDN.Imported.SizingShared
open Compliance Targets OuterGrayNativeModel PacketSizingRecords

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

tdn_data records : Records from "../../data/evidence/continuation/SizingShared.json" ["records"]
tdn_data installations : List PublicSARecord from "../../data/evidence/continuation/SizingShared.json" ["installations"]
tdn_data networks : List RedNetworkIdentity from "../../data/evidence/continuation/SizingShared.json" ["networks"]
tdn_data entries : List SourceEntry from "../../data/evidence/continuation/SizingShared.json" ["sourceEntries"]
tdn_data roles : List SizingRole from "../../data/evidence/continuation/SizingShared.json" ["sizingRoles"]
tdn_data attachments : List RedNetworkAttachment from "../../data/evidence/continuation/SizingShared.json" ["redNetworkAttachments"]
tdn_data epoch : String from "../../data/evidence/continuation/SizingShared.json" ["epoch"]

tdn_data linkPolicies : List (Nat × LinkAdmission.IfacePolicy) from "../../data/evidence/continuation/SizingShared.json" ["linkPolicies"]
tdn_data services : List ServiceRegistration from "../../data/evidence/continuation/SizingShared.json" ["services"]

tdn_data flows : List SourceFlow from "../../data/evidence/continuation/SizingShared.json" ["sourceFlows"]

end TDN.Imported.SizingShared
