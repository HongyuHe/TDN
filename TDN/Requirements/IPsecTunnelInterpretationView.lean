import TDN.Requirements.MasterMscRequirementSpecs

namespace TDN.Requirements.Msc
open Compliance

def associatedIPTunnelView (tunnel : Tunnel) : Tunnel :=
  if tunnel.mechanism = .ipsec then { tunnel with associatedIPTunnel := true } else tunnel

def deploymentWithAssociatedIPTunnels (d : Deployment) : Deployment :=
  { d with tunnels := d.tunnels.map associatedIPTunnelView }

@[simp] lemma associated_ip_tunnel_view_id (tunnel : Tunnel) :
    (associatedIPTunnelView tunnel).id = tunnel.id := by
  unfold associatedIPTunnelView
  split <;> rfl

@[simp] lemma associated_ip_tunnel_view_mechanism (tunnel : Tunnel) :
    (associatedIPTunnelView tunnel).mechanism = tunnel.mechanism := by
  unfold associatedIPTunnelView
  split <;> rfl

@[simp] lemma associated_ip_tunnel_view_layer (tunnel : Tunnel) :
    (associatedIPTunnelView tunnel).layer = tunnel.layer := by
  unfold associatedIPTunnelView
  split <;> rfl

@[simp] lemma associated_ip_tunnel_view_sender (tunnel : Tunnel) :
    (associatedIPTunnelView tunnel).sender = tunnel.sender := by
  unfold associatedIPTunnelView
  split <;> rfl

@[simp] lemma associated_ip_tunnel_view_receiver (tunnel : Tunnel) :
    (associatedIPTunnelView tunnel).receiver = tunnel.receiver := by
  unfold associatedIPTunnelView
  split <;> rfl

@[simp] lemma associated_ip_tunnel_view_key_context (tunnel : Tunnel) :
    (associatedIPTunnelView tunnel).keyContext = tunnel.keyContext := by
  unfold associatedIPTunnelView
  split <;> rfl

lemma processing_bound_with_associated_ip_tunnels {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (bound : binding.ProcessingBound d) :
    binding.ProcessingBound (deploymentWithAssociatedIPTunnels d) := by
  refine ⟨?_, bound.2⟩
  obtain ⟨inventory, processing, actors, tunnels, remaining⟩ := bound.1
  refine ⟨inventory, processing, actors, ?_, remaining⟩
  intro tunnel member mechanism
  obtain ⟨original, stored, rfl⟩ := List.mem_map.mp member
  simpa only [associated_ip_tunnel_view_id, associated_ip_tunnel_view_mechanism,
    associated_ip_tunnel_view_sender, associated_ip_tunnel_view_receiver] using
      tunnels original stored (by simpa only [associated_ip_tunnel_view_mechanism] using mechanism)

theorem coverage_with_associated_ip_tunnels {S A : Type} (model : ForwardingModel S A)
    (d : Deployment) (covered : model.CoversDeployment d) :
    model.CoversDeployment (deploymentWithAssociatedIPTunnels d) := by
  obtain ⟨processing, faithful, steps, sources, history, links, linkPolicies, headers, reachable,
    macsecKeys, ipsecKeys, networks, peers, devices, interfaces, tunnels, indices, records,
    physical, entries, macsec, ipsec⟩ := covered
  refine ⟨processing_bound_with_associated_ip_tunnels model.native d processing, faithful, steps, sources,
    history, links, linkPolicies, headers, reachable, macsecKeys, ipsecKeys, networks, ?_, devices, interfaces,
    ?_, indices, records, physical, entries, ?_, ?_⟩
  · intro tunnel member
    obtain ⟨original, stored, rfl⟩ := List.mem_map.mp member
    change d.intendedPeer (associatedIPTunnelView original).sender (associatedIPTunnelView original).receiver
    simpa only [associated_ip_tunnel_view_sender, associated_ip_tunnel_view_receiver] using peers original stored
  · intro first firstMember second secondMember same
    obtain ⟨originalFirst, storedFirst, rfl⟩ := List.mem_map.mp firstMember
    obtain ⟨originalSecond, storedSecond, rfl⟩ := List.mem_map.mp secondMember
    have identity := tunnels originalFirst storedFirst originalSecond storedSecond
      (by simpa only [associated_ip_tunnel_view_id] using same)
    rw [identity]
  · intro iface configured association installed
    obtain ⟨tunnel, stored, identity, mechanism, key, sender, receivers⟩ := macsec iface configured association installed
    refine ⟨associatedIPTunnelView tunnel, List.mem_map.mpr ⟨tunnel, stored, rfl⟩, ?_⟩
    simpa only [associated_ip_tunnel_view_id, associated_ip_tunnel_view_mechanism,
      associated_ip_tunnel_view_key_context, associated_ip_tunnel_view_sender, associated_ip_tunnel_view_receiver]
      using And.intro identity ⟨mechanism, key, sender, receivers⟩
  · intro iface association policy installed bound
    obtain ⟨tunnel, stored, identity, mechanism, sender, receiver⟩ := ipsec iface association policy installed bound
    refine ⟨associatedIPTunnelView tunnel, List.mem_map.mpr ⟨tunnel, stored, rfl⟩, ?_⟩
    simpa only [associated_ip_tunnel_view_id, associated_ip_tunnel_view_mechanism,
      associated_ip_tunnel_view_sender, associated_ip_tunnel_view_receiver] using
        And.intro identity ⟨mechanism, sender, receiver⟩

end TDN.Requirements.Msc
