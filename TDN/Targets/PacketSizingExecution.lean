import TDN.Targets.CompleteSpecifications
import TDN.Semantics.WholePacketEmission

namespace TDN.Targets.Complete
open Compliance

def WireSizeModel.fragmentOnlyWhenNeeded {S : Type} (sizes : WireSizeModel S)
    (iface : S → Nat) : WireSizeModel S :=
  { sizes with emission := fun state =>
      (sizes.emission state).fragmentOnlyWhenNeeded (sizes.configuredMtu (iface state)) }

theorem fitting_wire_budget_uses_one_fragment {S A : Type}
    (model : ExecutionModel S A) (sizes : WireSizeModel S) (settings : List PacketSizing)
    (profiles : List FragmentationProfile)
    (correspondence : sizes.Correspondence model settings)
    (budgets : Primitive_msc_packet_size_configuration settings profiles) :
    (sizes.fragmentOnlyWhenNeeded (fun state => (model.native.state state).iface)).NoFurtherFragmentation
      model settings := by
  intro start actions before action after setting initialized run step wire member iface role
  have bounds := (correspondence.2.2.2 start actions before action after initialized run step wire).2
    setting member iface
  have encodedFits := ((budgets setting member).1 role).2.2.2 _ bounds.1
  have settingsMatch := correspondence.2.1 setting member
  have fits : (sizes.emission before).MtuBytes ≤
      sizes.configuredMtu (model.native.state before).iface := by
    rw [← iface, ← settingsMatch.1]
    exact bounds.2.trans encodedFits
  exact PacketSource.Datagram.fitting_packet_uses_one_fragment (sizes.emission before) _ fits

end TDN.Targets.Complete
