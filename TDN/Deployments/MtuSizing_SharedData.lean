import TDN.Deployments.MtuSizing_Records

namespace TDN.Deployments.MtuSizing_Shared
open Compliance Requirements OuterToGray_DeviceModel MtuSizing_Records

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

load_network_records records : Records from "../../data/evidence/continuation/MtuSizing_Shared.json" ["records"]
load_network_records installations : List PublicSARecord from "../../data/evidence/continuation/MtuSizing_Shared.json" ["installations"]
load_network_records networks : List RedNetworkIdentity from "../../data/evidence/continuation/MtuSizing_Shared.json" ["networks"]
load_network_records entries : List SourceEntry from "../../data/evidence/continuation/MtuSizing_Shared.json" ["sourceEntries"]
load_network_records roles : List SizingRole from "../../data/evidence/continuation/MtuSizing_Shared.json" ["sizingRoles"]
load_network_records attachments : List RedNetworkAttachment from "../../data/evidence/continuation/MtuSizing_Shared.json" ["redNetworkAttachments"]
load_network_records epoch : String from "../../data/evidence/continuation/MtuSizing_Shared.json" ["epoch"]

load_network_records linkPolicies : List (Nat × LinkAdmission.IfacePolicy) from "../../data/evidence/continuation/MtuSizing_Shared.json" ["linkPolicies"]
load_network_records services : List ServiceRegistration from "../../data/evidence/continuation/MtuSizing_Shared.json" ["services"]

load_network_records flows : List SourceFlow from "../../data/evidence/continuation/MtuSizing_Shared.json" ["sourceFlows"]

end TDN.Deployments.MtuSizing_Shared
