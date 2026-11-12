import TDN.Import

/-! Live BIRD observations collected through the MCP server on October 31, 2026. -/
namespace TDN.ImportTests

load_network_snapshot Bird from "../../data/evidence/20261031T165203Z-aa3dae3f2fdc.json"

lemma every_route_has_observed_source : TDN.Import.RoutesHaveSources Bird.snapshot := by native_decide

lemma bird_a_installed_peer_route :
    ∃ route ∈ Bird.snapshot.routes,
      route.device = "bird-a" ∧ route.protocol = "bird" ∧
      route.destinationLow = 172818944 ∧ route.prefixLength = 24 ∧
      route.gateway = some 2887706380 ∧ route.output = some "eth0" := by native_decide

end TDN.ImportTests
