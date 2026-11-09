import TDN.Requirements.ExtractAllowedIpProtocols

namespace TDN.Requirements.Msc
open Compliance MultiProtocolForwarding

def RouteOwnersCoherent (configuration : Config) : Prop :=
  ∀ route ∈ configuration.ip.routes,
    configuration.ip.owner route.ingress = configuration.ip.owner route.egress

lemma device_route_preserves_owner (configuration : Config)
    (owners : RouteOwnersCoherent configuration)
    {before after : MultiProtocolForwarding.State}
    (route : MultiProtocolForwarding.Step configuration before .route after) :
    configuration.ip.owner after.iface = configuration.ip.owner before.iface := by
  cases route with
  | route route datapathStage visible selected entry =>
    simpa only [entry] using (owners route selected.1).symm
  | routeLocalOutput route datapathStage visible selected entry =>
    simpa only [entry] using (owners route selected.1).symm
  | routeOuterPacket route datapathStage visible selected entry =>
    simpa only [entry] using (owners route selected.1).symm

lemma device_context_preserves_owner (configuration : Config)
    (owners : RouteOwnersCoherent configuration) (context : PacketProcessing.Context)
    (atHook : context.AtHook configuration) :
    configuration.ip.owner context.state.iface = configuration.ip.owner context.entry.iface := by
  cases hook : context.hook with
  | input =>
    simp only [PacketProcessing.Context.AtHook, hook] at atHook
    obtain ⟨_, ingress, _⟩ := atHook
    exact congrArg configuration.ip.owner (ingress_has_native_ifaces ingress).1
  | forward =>
    simp only [PacketProcessing.Context.AtHook, hook] at atHook
    obtain ⟨_, entered, route, ingress, _, routed, _⟩ := atHook
    exact (device_route_preserves_owner configuration owners routed).trans
      (congrArg configuration.ip.owner (ingress_has_native_ifaces ingress).1)
  | output =>
    simp only [PacketProcessing.Context.AtHook, hook] at atHook
    exact device_route_preserves_owner configuration owners atHook.2.2.1
  | link => simp [PacketProcessing.Context.AtHook, hook] at atHook

lemma device_outbound_suffix_preserves_owner (configuration : Config)
    (owners : RouteOwnersCoherent configuration)
    {filtered ready : MultiProtocolForwarding.State}
    (suffix : OutboundSuffix configuration filtered ready) :
    configuration.ip.owner ready.iface = configuration.ip.owner filtered.iface := by
  cases suffix with
  | forwardWithoutEncap step datapathStage =>
    cases step <;> simp_all
  | IPsec protect route =>
    have selectedOwner := device_route_preserves_owner configuration owners route
    cases protect
    exact selectedOwner

theorem boundary_view_preserves_owner (configuration : Config)
    (owners : RouteOwnersCoherent configuration) (context : PacketProcessing.Context)
    (atHook : context.AtHook configuration)
    (direction : Direction) (iface : Nat) (packet : PacketPolicy.Packet)
    (view : DeviceBoundaryView configuration context direction iface packet) :
    configuration.ip.owner iface = configuration.ip.owner context.state.iface := by
  cases view with
  | inbound =>
    exact (device_context_preserves_owner configuration owners context atHook).symm
  | outbound filtered ready afterWire filter run wire header visible =>
    have preserved := boundary_filter_preserves_frame_and_iface configuration context filtered filter
    have suffix := first_ready_run_from_filtered_is_native_suffix configuration preserved.2.2 run
    exact (device_outbound_suffix_preserves_owner configuration owners suffix).trans
      (congrArg configuration.ip.owner preserved.2.1)

end TDN.Requirements.Msc
