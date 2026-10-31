import TDN.Targets.ServicePlacement

namespace TDN.Imported.FreshRedTimePlacement

def networkZone (bridge : String) : Zone := if bridge = "nd3b0" then .red else .black
def insideBridge : String := "nd3b0"
def serviceBridge : String := "nd3b0"

theorem actual_time_source_is_on_selected_red_network : networkZone serviceBridge = .red :=
  Targets.service_location_from_shared_bridge networkZone insideBridge serviceBridge (by decide) (by decide)

end TDN.Imported.FreshRedTimePlacement
