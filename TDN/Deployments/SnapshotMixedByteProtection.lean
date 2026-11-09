import TDN.Requirements.HybridIpsecMacsecByteProtection
import TDN.Deployments.TunnelMatrix_EncapStackChecks
import TDN.Deployments.SnapshotBridgedMacsecChecks
import TDN.Deployments.SnapshotMixedDeliverySuite

namespace TDN.Deployments.PairingIpsecIpsecIntegrated
open MultiProtocolForwarding

theorem every_mixed_byte_keeps_stack {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolForwarding.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolForwarding.Action)}
    (run : (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr [] actions after) :
    ByteFlows.Safe (fun _ => EncapStackConsistent config expectedEncapStack) after :=
  Requirements.mixed_bytes_keep_protection config expectedEncapStack redSources mixed_local_conditions
    red_sources_checked run

theorem every_mixed_black_byte_has_actual_layer_order {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolForwarding.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolForwarding.Action)}
    (run : (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr [] actions after)
    (packet : ByteFlows.Carrier MultiProtocolForwarding.State Byte) (member : packet ∈ after)
    (ready : packet.state.datapathStage = .egressReady) (black : packet.state.iface ∈ blackIfaces)
    (byte : Byte) (contains : byte ∈ packet.bytes) :
    packet.state.frame.body.protectionLayers = [2, 1] ∧
    ∃ start labels, Requirements.MixedByteOrigin redSources start byte ∧
      (byteLineage config).MTr start labels packet.state ∧
      ByteOrderedEncryptions config 1 2 start labels packet.state :=
  Requirements.every_mixed_black_byte_has_ordered_encryptions config expectedEncapStack redSources blackIfaces
    mixed_local_conditions red_sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (DataPlaneForwarding.iface_at_member_or_default ifaces iface))
    run packet member ready black byte contains

end TDN.Deployments.PairingIpsecIpsecIntegrated

namespace TDN.Deployments.PairingIpsecMacsecIntegrated
open MultiProtocolForwarding

theorem every_mixed_byte_keeps_stack {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolForwarding.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolForwarding.Action)}
    (run : (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr [] actions after) :
    ByteFlows.Safe (fun _ => EncapStackConsistent config expectedEncapStack) after :=
  Requirements.mixed_bytes_keep_protection config expectedEncapStack redSources mixed_local_conditions
    red_sources_checked run

theorem every_mixed_black_byte_has_actual_layer_order {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolForwarding.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolForwarding.Action)}
    (run : (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr [] actions after)
    (packet : ByteFlows.Carrier MultiProtocolForwarding.State Byte) (member : packet ∈ after)
    (ready : packet.state.datapathStage = .egressReady) (black : packet.state.iface ∈ blackIfaces)
    (byte : Byte) (contains : byte ∈ packet.bytes) :
    packet.state.frame.body.protectionLayers = [2, 1] ∧
    ∃ start labels, Requirements.MixedByteOrigin redSources start byte ∧
      (byteLineage config).MTr start labels packet.state ∧
      ByteOrderedEncryptions config 1 2 start labels packet.state :=
  Requirements.every_mixed_black_byte_has_ordered_encryptions config expectedEncapStack redSources blackIfaces
    mixed_local_conditions red_sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (DataPlaneForwarding.iface_at_member_or_default ifaces iface))
    run packet member ready black byte contains

end TDN.Deployments.PairingIpsecMacsecIntegrated

namespace TDN.Deployments.PairingMacsecIpsecIntegrated
open MultiProtocolForwarding

theorem every_mixed_byte_keeps_stack {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolForwarding.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolForwarding.Action)}
    (run : (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr [] actions after) :
    ByteFlows.Safe (fun _ => EncapStackConsistent config expectedEncapStack) after :=
  Requirements.mixed_bytes_keep_protection config expectedEncapStack redSources mixed_local_conditions
    red_sources_checked run

theorem every_mixed_black_byte_has_actual_layer_order {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolForwarding.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolForwarding.Action)}
    (run : (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr [] actions after)
    (packet : ByteFlows.Carrier MultiProtocolForwarding.State Byte) (member : packet ∈ after)
    (ready : packet.state.datapathStage = .egressReady) (black : packet.state.iface ∈ blackIfaces)
    (byte : Byte) (contains : byte ∈ packet.bytes) :
    packet.state.frame.body.protectionLayers = [2, 1] ∧
    ∃ start labels, Requirements.MixedByteOrigin redSources start byte ∧
      (byteLineage config).MTr start labels packet.state ∧
      ByteOrderedEncryptions config 1 2 start labels packet.state :=
  Requirements.every_mixed_black_byte_has_ordered_encryptions config expectedEncapStack redSources blackIfaces
    mixed_local_conditions red_sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (DataPlaneForwarding.iface_at_member_or_default ifaces iface))
    run packet member ready black byte contains

end TDN.Deployments.PairingMacsecIpsecIntegrated

namespace TDN.Deployments.PairingMacsecIpsecStandalone
open MultiProtocolForwarding

theorem every_mixed_byte_keeps_stack {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolForwarding.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolForwarding.Action)}
    (run : (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr [] actions after) :
    ByteFlows.Safe (fun _ => EncapStackConsistent config expectedEncapStack) after :=
  Requirements.mixed_bytes_keep_protection config expectedEncapStack redSources mixed_local_conditions
    red_sources_checked run

theorem every_mixed_black_byte_has_actual_layer_order {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolForwarding.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolForwarding.Action)}
    (run : (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr [] actions after)
    (packet : ByteFlows.Carrier MultiProtocolForwarding.State Byte) (member : packet ∈ after)
    (ready : packet.state.datapathStage = .egressReady) (black : packet.state.iface ∈ blackIfaces)
    (byte : Byte) (contains : byte ∈ packet.bytes) :
    packet.state.frame.body.protectionLayers = [2, 1] ∧
    ∃ start labels, Requirements.MixedByteOrigin redSources start byte ∧
      (byteLineage config).MTr start labels packet.state ∧
      ByteOrderedEncryptions config 1 2 start labels packet.state :=
  Requirements.every_mixed_black_byte_has_ordered_encryptions config expectedEncapStack redSources blackIfaces
    mixed_local_conditions red_sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (DataPlaneForwarding.iface_at_member_or_default ifaces iface))
    run packet member ready black byte contains

end TDN.Deployments.PairingMacsecIpsecStandalone

namespace TDN.Deployments.PairingMacsecMacsecIntegrated
open MultiProtocolForwarding

theorem every_mixed_byte_keeps_stack {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolForwarding.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolForwarding.Action)}
    (run : (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr [] actions after) :
    ByteFlows.Safe (fun _ => EncapStackConsistent config expectedEncapStack) after :=
  Requirements.mixed_bytes_keep_protection config expectedEncapStack redSources mixed_local_conditions
    red_sources_checked run

theorem every_mixed_black_byte_has_actual_layer_order {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolForwarding.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolForwarding.Action)}
    (run : (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr [] actions after)
    (packet : ByteFlows.Carrier MultiProtocolForwarding.State Byte) (member : packet ∈ after)
    (ready : packet.state.datapathStage = .egressReady) (black : packet.state.iface ∈ blackIfaces)
    (byte : Byte) (contains : byte ∈ packet.bytes) :
    packet.state.frame.body.protectionLayers = [2, 1] ∧
    ∃ start labels, Requirements.MixedByteOrigin redSources start byte ∧
      (byteLineage config).MTr start labels packet.state ∧
      ByteOrderedEncryptions config 1 2 start labels packet.state :=
  Requirements.every_mixed_black_byte_has_ordered_encryptions config expectedEncapStack redSources blackIfaces
    mixed_local_conditions red_sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (DataPlaneForwarding.iface_at_member_or_default ifaces iface))
    run packet member ready black byte contains

end TDN.Deployments.PairingMacsecMacsecIntegrated

namespace TDN.Deployments.PairingMacsecMacsecStandalone
open MultiProtocolForwarding

theorem every_mixed_byte_keeps_stack {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolForwarding.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolForwarding.Action)}
    (run : (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr [] actions after) :
    ByteFlows.Safe (fun _ => EncapStackConsistent config expectedEncapStack) after :=
  Requirements.mixed_bytes_keep_protection config expectedEncapStack redSources mixed_local_conditions
    red_sources_checked run

theorem every_mixed_black_byte_has_actual_layer_order {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolForwarding.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolForwarding.Action)}
    (run : (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr [] actions after)
    (packet : ByteFlows.Carrier MultiProtocolForwarding.State Byte) (member : packet ∈ after)
    (ready : packet.state.datapathStage = .egressReady) (black : packet.state.iface ∈ blackIfaces)
    (byte : Byte) (contains : byte ∈ packet.bytes) :
    packet.state.frame.body.protectionLayers = [2, 1] ∧
    ∃ start labels, Requirements.MixedByteOrigin redSources start byte ∧
      (byteLineage config).MTr start labels packet.state ∧
      ByteOrderedEncryptions config 1 2 start labels packet.state :=
  Requirements.every_mixed_black_byte_has_ordered_encryptions config expectedEncapStack redSources blackIfaces
    mixed_local_conditions red_sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (DataPlaneForwarding.iface_at_member_or_default ifaces iface))
    run packet member ready black byte contains

end TDN.Deployments.PairingMacsecMacsecStandalone

namespace TDN.Deployments.PairingInnerMacsecOuterIpsec
open MultiProtocolForwarding

theorem every_mixed_byte_keeps_stack {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolForwarding.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolForwarding.Action)}
    (run : (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr [] actions after) :
    ByteFlows.Safe (fun _ => EncapStackConsistent config expectedEncapStack) after :=
  Requirements.mixed_bytes_keep_protection config expectedEncapStack redSources mixed_local_conditions
    red_sources_checked run

theorem every_mixed_black_byte_has_actual_layer_order {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolForwarding.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolForwarding.Action)}
    (run : (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr [] actions after)
    (packet : ByteFlows.Carrier MultiProtocolForwarding.State Byte) (member : packet ∈ after)
    (ready : packet.state.datapathStage = .egressReady) (black : packet.state.iface ∈ blackIfaces)
    (byte : Byte) (contains : byte ∈ packet.bytes) :
    packet.state.frame.body.protectionLayers = [2, 1] ∧
    ∃ start labels, Requirements.MixedByteOrigin redSources start byte ∧
      (byteLineage config).MTr start labels packet.state ∧
      ByteOrderedEncryptions config 1 2 start labels packet.state :=
  Requirements.every_mixed_black_byte_has_ordered_encryptions config expectedEncapStack redSources blackIfaces
    mixed_local_conditions red_sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (DataPlaneForwarding.iface_at_member_or_default ifaces iface))
    run packet member ready black byte contains

end TDN.Deployments.PairingInnerMacsecOuterIpsec

namespace TDN.Deployments.PairingIpsecIpsecIntegrated.Forward
open MultiProtocolForwarding

theorem positive_three_byte_delivery :
    (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState39, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Requirements.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Requirements.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Deployments.PairingIpsecIpsecIntegrated.Forward

namespace TDN.Deployments.PairingIpsecIpsecIntegrated.Reverse
open MultiProtocolForwarding

theorem positive_three_byte_delivery :
    (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState39, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Requirements.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Requirements.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Deployments.PairingIpsecIpsecIntegrated.Reverse

namespace TDN.Deployments.PairingIpsecMacsecIntegrated.Forward
open MultiProtocolForwarding

theorem positive_three_byte_delivery :
    (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState32, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Requirements.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Requirements.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Deployments.PairingIpsecMacsecIntegrated.Forward

namespace TDN.Deployments.PairingIpsecMacsecIntegrated.Reverse
open MultiProtocolForwarding

theorem positive_three_byte_delivery :
    (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState32, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Requirements.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Requirements.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Deployments.PairingIpsecMacsecIntegrated.Reverse

namespace TDN.Deployments.PairingMacsecIpsecIntegrated.Forward
open MultiProtocolForwarding

theorem positive_three_byte_delivery :
    (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState41, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Requirements.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Requirements.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Deployments.PairingMacsecIpsecIntegrated.Forward

namespace TDN.Deployments.PairingMacsecIpsecIntegrated.Reverse
open MultiProtocolForwarding

theorem positive_three_byte_delivery :
    (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState41, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Requirements.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Requirements.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Deployments.PairingMacsecIpsecIntegrated.Reverse

namespace TDN.Deployments.PairingMacsecIpsecStandalone.Forward
open MultiProtocolForwarding

theorem positive_three_byte_delivery :
    (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState51, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Requirements.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Requirements.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Deployments.PairingMacsecIpsecStandalone.Forward

namespace TDN.Deployments.PairingMacsecIpsecStandalone.Reverse
open MultiProtocolForwarding

theorem positive_three_byte_delivery :
    (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState51, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Requirements.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Requirements.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Deployments.PairingMacsecIpsecStandalone.Reverse

namespace TDN.Deployments.PairingMacsecMacsecIntegrated.Forward
open MultiProtocolForwarding

theorem positive_three_byte_delivery :
    (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState34, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Requirements.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Requirements.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Deployments.PairingMacsecMacsecIntegrated.Forward

namespace TDN.Deployments.PairingMacsecMacsecIntegrated.Reverse
open MultiProtocolForwarding

theorem positive_three_byte_delivery :
    (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState34, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Requirements.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Requirements.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Deployments.PairingMacsecMacsecIntegrated.Reverse

namespace TDN.Deployments.PairingMacsecMacsecStandalone.Forward
open MultiProtocolForwarding

theorem positive_three_byte_delivery :
    (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState44, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Requirements.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Requirements.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Deployments.PairingMacsecMacsecStandalone.Forward

namespace TDN.Deployments.PairingMacsecMacsecStandalone.Reverse
open MultiProtocolForwarding

theorem positive_three_byte_delivery :
    (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState44, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Requirements.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Requirements.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Deployments.PairingMacsecMacsecStandalone.Reverse

namespace TDN.Deployments.PairingInnerMacsecOuterIpsec.ForwardVLAN0
open MultiProtocolForwarding

theorem positive_three_byte_delivery :
    (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState30, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Requirements.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Requirements.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Deployments.PairingInnerMacsecOuterIpsec.ForwardVLAN0

namespace TDN.Deployments.PairingInnerMacsecOuterIpsec.ForwardVLAN1
open MultiProtocolForwarding

theorem positive_three_byte_delivery :
    (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState30, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Requirements.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Requirements.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Deployments.PairingInnerMacsecOuterIpsec.ForwardVLAN1

namespace TDN.Deployments.PairingInnerMacsecOuterIpsec.ForwardVLAN2
open MultiProtocolForwarding

theorem positive_three_byte_delivery :
    (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState30, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Requirements.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Requirements.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Deployments.PairingInnerMacsecOuterIpsec.ForwardVLAN2

namespace TDN.Deployments.PairingInnerMacsecOuterIpsec.ReverseVLAN0
open MultiProtocolForwarding

theorem positive_three_byte_delivery :
    (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState30, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Requirements.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Requirements.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Deployments.PairingInnerMacsecOuterIpsec.ReverseVLAN0

namespace TDN.Deployments.PairingInnerMacsecOuterIpsec.ReverseVLAN1
open MultiProtocolForwarding

theorem positive_three_byte_delivery :
    (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState30, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Requirements.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Requirements.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Deployments.PairingInnerMacsecOuterIpsec.ReverseVLAN1

namespace TDN.Deployments.PairingInnerMacsecOuterIpsec.ReverseVLAN2
open MultiProtocolForwarding

theorem positive_three_byte_delivery :
    (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState30, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Requirements.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Requirements.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Deployments.PairingInnerMacsecOuterIpsec.ReverseVLAN2
