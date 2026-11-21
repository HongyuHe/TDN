import TDN.Requirements.MscRequirements

namespace TDN.Requirements.Msc
open Compliance

structure RedLabelAssignment where
  network : String
  innerDevice : String
  level : SecurityLevel

def labeledNetwork (assigned : List RedLabelAssignment) (network : RedNetworkIdentity) : RedNetworkIdentity :=
  { network with level := ((assigned.find? (fun row => row.network == network.id)).map
      RedLabelAssignment.level).getD network.level }

def labeledComponent (assigned : List RedLabelAssignment) (device : Device) : Device :=
  { device with level := ((assigned.find? (fun row => row.innerDevice == device.id)).map
      RedLabelAssignment.level).getD device.level }

def deploymentWithRedLabels (d : Deployment) (assigned : List RedLabelAssignment) : Deployment :=
  { d with
    networks := d.networks.map (labeledNetwork assigned)
    devices := d.devices.map (labeledComponent assigned) }

private lemma exists_mapped_record {α β : Type} (f : α → β) (xs : List α) (p : β → Prop) :
    (∃ y ∈ xs.map f, p y) ↔ ∃ x ∈ xs, p (f x) := by
  constructor
  · rintro ⟨y, member, ok⟩
    obtain ⟨x, hx, rfl⟩ := List.mem_map.mp member
    exact ⟨x, hx, ok⟩
  · rintro ⟨x, member, ok⟩
    exact ⟨f x, List.mem_map.mpr ⟨x, member, rfl⟩, ok⟩

theorem red_label_assignment_preserves_coverage {S A : Type} (model : ForwardingModel S A)
    (d : Deployment) (assigned : List RedLabelAssignment)
    (redName : Nat → String) (red : ∀ domain, model.deviceDataPlane.origin domain = .red (redName domain))
    (udp : d.udpBindings = []) (covered : model.CoversDeployment d) :
    model.CoversDeployment (deploymentWithRedLabels d assigned) := by
  obtain ⟨processing, faithful, steps, sources, history, links, linkPolicies, headers, reachable,
    macsecKeys, ipsecKeys, nonempty, peers, unique, interfaces, tunnels, indices, records,
    physical, entries, macsec, ipsec⟩ := covered
  refine ⟨?_, faithful, steps, ?_, history, links, linkPolicies, headers, reachable,
    macsecKeys, ipsecKeys, ?_, peers, ?_, interfaces, tunnels, indices, records, physical, ?_,
    macsec, ipsec⟩
  · exact ⟨processing.1, by simp [Deployment.UDPBindingsCoherent, deploymentWithRedLabels, udp],
      processing.2.2⟩
  · simpa only [ForwardingModel.SourceCoverage, DeviceExecutionBinding.SourceInitial,
      DeviceExecutionBinding.SourceDatagram, DeviceExecutionBinding.SourceRequestAllowed,
      red, deploymentWithRedLabels, List.forall_mem_map, exists_mapped_record, labeledNetwork] using sources
  · simpa only [deploymentWithRedLabels, ne_eq, List.map_eq_nil_iff] using nonempty
  · intro first firstMember last lastMember same
    obtain ⟨a, aMember, rfl⟩ := List.mem_map.mp firstMember
    obtain ⟨b, bMember, rfl⟩ := List.mem_map.mp lastMember
    exact congrArg (labeledComponent assigned) (unique a aMember b bMember same)
  · intro iface name
    simpa only [deploymentWithRedLabels, exists_mapped_record, labeledNetwork] using entries iface name

end TDN.Requirements.Msc
