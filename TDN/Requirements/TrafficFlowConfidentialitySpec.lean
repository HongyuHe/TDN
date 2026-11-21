import TDN.Models.ConstantRateCoverTraffic

namespace TDN.Requirements

structure TrafficFlowConfidentialityUse where
  publicInternet : Bool
  externalMACsec : Bool
  outerFirewallAttached : Bool
  objectiveSelected : Bool
  enabled : Bool
  deriving DecidableEq, Repr

def msc_traffic_flow_confidentiality (uses : List TrafficFlowConfidentialityUse) : Prop :=
  ∀ use ∈ uses,
    (use.publicInternet = true → use.enabled = true) ∧
    (use.objectiveSelected = true → use.externalMACsec = true →
      use.outerFirewallAttached = true → use.enabled = true)

def ScheduledCoverGuarantee (config : CoverTraffic.ScheduleConfig) : Prop :=
  config.Valid ∧
  ∀ firstDeadline actions finish,
    (CoverTraffic.system config).MTr (CoverTraffic.initial firstDeadline) actions finish →
      CoverTraffic.Safe config finish

structure CoverInstallation where
  device : String
  use : TrafficFlowConfidentialityUse
  sender : CoverTraffic.ScheduleConfig
  active : Bool
  deriving DecidableEq, Repr

end TDN.Requirements
