import TDN.Targets.MixedByteProtection
import TDN.Evidence.FreshPairingStackChecks
import TDN.Evidence.FreshBridgedMACsecChecks
import TDN.Evidence.FreshMixedDeliverySuite

namespace TDN.Imported.PairingIpsecIpsecIntegrated
open MultiProtocolExecution

theorem every_mixed_byte_keeps_stack {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolExecution.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolExecution.Action)}
    (run : (byteSystem config (Targets.MixedByteOrigin redSources)).MTr [] actions after) :
    ByteFlows.Safe (fun _ => StackInvariant config layout) after :=
  Targets.mixed_bytes_keep_protection config layout redSources mixed_local_conditions
    red_sources_checked run

theorem every_mixed_black_byte_has_actual_layer_order {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolExecution.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolExecution.Action)}
    (run : (byteSystem config (Targets.MixedByteOrigin redSources)).MTr [] actions after)
    (packet : ByteFlows.Carrier MultiProtocolExecution.State Byte) (member : packet ∈ after)
    (ready : packet.state.phase = .ready) (black : packet.state.port ∈ blackPorts)
    (byte : Byte) (contains : byte ∈ packet.bytes) :
    packet.state.frame.body.protectionLayers = [2, 1] ∧
    ∃ start labels, Targets.MixedByteOrigin redSources start byte ∧
      (byteLineage config).MTr start labels packet.state ∧
      ByteOrderedEncryptions config 1 2 start labels packet.state :=
  Targets.every_mixed_black_byte_has_ordered_encryptions config layout redSources blackPorts
    mixed_local_conditions red_sources_checked black_ports_checked
    (fun port => outer_port_shapes _ (Execution.port_at_member_or_default ports port))
    run packet member ready black byte contains

end TDN.Imported.PairingIpsecIpsecIntegrated

namespace TDN.Imported.PairingIpsecMacsecIntegrated
open MultiProtocolExecution

theorem every_mixed_byte_keeps_stack {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolExecution.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolExecution.Action)}
    (run : (byteSystem config (Targets.MixedByteOrigin redSources)).MTr [] actions after) :
    ByteFlows.Safe (fun _ => StackInvariant config layout) after :=
  Targets.mixed_bytes_keep_protection config layout redSources mixed_local_conditions
    red_sources_checked run

theorem every_mixed_black_byte_has_actual_layer_order {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolExecution.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolExecution.Action)}
    (run : (byteSystem config (Targets.MixedByteOrigin redSources)).MTr [] actions after)
    (packet : ByteFlows.Carrier MultiProtocolExecution.State Byte) (member : packet ∈ after)
    (ready : packet.state.phase = .ready) (black : packet.state.port ∈ blackPorts)
    (byte : Byte) (contains : byte ∈ packet.bytes) :
    packet.state.frame.body.protectionLayers = [2, 1] ∧
    ∃ start labels, Targets.MixedByteOrigin redSources start byte ∧
      (byteLineage config).MTr start labels packet.state ∧
      ByteOrderedEncryptions config 1 2 start labels packet.state :=
  Targets.every_mixed_black_byte_has_ordered_encryptions config layout redSources blackPorts
    mixed_local_conditions red_sources_checked black_ports_checked
    (fun port => outer_port_shapes _ (Execution.port_at_member_or_default ports port))
    run packet member ready black byte contains

end TDN.Imported.PairingIpsecMacsecIntegrated

namespace TDN.Imported.PairingMacsecIpsecIntegrated
open MultiProtocolExecution

theorem every_mixed_byte_keeps_stack {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolExecution.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolExecution.Action)}
    (run : (byteSystem config (Targets.MixedByteOrigin redSources)).MTr [] actions after) :
    ByteFlows.Safe (fun _ => StackInvariant config layout) after :=
  Targets.mixed_bytes_keep_protection config layout redSources mixed_local_conditions
    red_sources_checked run

theorem every_mixed_black_byte_has_actual_layer_order {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolExecution.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolExecution.Action)}
    (run : (byteSystem config (Targets.MixedByteOrigin redSources)).MTr [] actions after)
    (packet : ByteFlows.Carrier MultiProtocolExecution.State Byte) (member : packet ∈ after)
    (ready : packet.state.phase = .ready) (black : packet.state.port ∈ blackPorts)
    (byte : Byte) (contains : byte ∈ packet.bytes) :
    packet.state.frame.body.protectionLayers = [2, 1] ∧
    ∃ start labels, Targets.MixedByteOrigin redSources start byte ∧
      (byteLineage config).MTr start labels packet.state ∧
      ByteOrderedEncryptions config 1 2 start labels packet.state :=
  Targets.every_mixed_black_byte_has_ordered_encryptions config layout redSources blackPorts
    mixed_local_conditions red_sources_checked black_ports_checked
    (fun port => outer_port_shapes _ (Execution.port_at_member_or_default ports port))
    run packet member ready black byte contains

end TDN.Imported.PairingMacsecIpsecIntegrated

namespace TDN.Imported.PairingMacsecIpsecStandalone
open MultiProtocolExecution

theorem every_mixed_byte_keeps_stack {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolExecution.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolExecution.Action)}
    (run : (byteSystem config (Targets.MixedByteOrigin redSources)).MTr [] actions after) :
    ByteFlows.Safe (fun _ => StackInvariant config layout) after :=
  Targets.mixed_bytes_keep_protection config layout redSources mixed_local_conditions
    red_sources_checked run

theorem every_mixed_black_byte_has_actual_layer_order {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolExecution.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolExecution.Action)}
    (run : (byteSystem config (Targets.MixedByteOrigin redSources)).MTr [] actions after)
    (packet : ByteFlows.Carrier MultiProtocolExecution.State Byte) (member : packet ∈ after)
    (ready : packet.state.phase = .ready) (black : packet.state.port ∈ blackPorts)
    (byte : Byte) (contains : byte ∈ packet.bytes) :
    packet.state.frame.body.protectionLayers = [2, 1] ∧
    ∃ start labels, Targets.MixedByteOrigin redSources start byte ∧
      (byteLineage config).MTr start labels packet.state ∧
      ByteOrderedEncryptions config 1 2 start labels packet.state :=
  Targets.every_mixed_black_byte_has_ordered_encryptions config layout redSources blackPorts
    mixed_local_conditions red_sources_checked black_ports_checked
    (fun port => outer_port_shapes _ (Execution.port_at_member_or_default ports port))
    run packet member ready black byte contains

end TDN.Imported.PairingMacsecIpsecStandalone

namespace TDN.Imported.PairingMacsecMacsecIntegrated
open MultiProtocolExecution

theorem every_mixed_byte_keeps_stack {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolExecution.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolExecution.Action)}
    (run : (byteSystem config (Targets.MixedByteOrigin redSources)).MTr [] actions after) :
    ByteFlows.Safe (fun _ => StackInvariant config layout) after :=
  Targets.mixed_bytes_keep_protection config layout redSources mixed_local_conditions
    red_sources_checked run

theorem every_mixed_black_byte_has_actual_layer_order {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolExecution.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolExecution.Action)}
    (run : (byteSystem config (Targets.MixedByteOrigin redSources)).MTr [] actions after)
    (packet : ByteFlows.Carrier MultiProtocolExecution.State Byte) (member : packet ∈ after)
    (ready : packet.state.phase = .ready) (black : packet.state.port ∈ blackPorts)
    (byte : Byte) (contains : byte ∈ packet.bytes) :
    packet.state.frame.body.protectionLayers = [2, 1] ∧
    ∃ start labels, Targets.MixedByteOrigin redSources start byte ∧
      (byteLineage config).MTr start labels packet.state ∧
      ByteOrderedEncryptions config 1 2 start labels packet.state :=
  Targets.every_mixed_black_byte_has_ordered_encryptions config layout redSources blackPorts
    mixed_local_conditions red_sources_checked black_ports_checked
    (fun port => outer_port_shapes _ (Execution.port_at_member_or_default ports port))
    run packet member ready black byte contains

end TDN.Imported.PairingMacsecMacsecIntegrated

namespace TDN.Imported.PairingMacsecMacsecStandalone
open MultiProtocolExecution

theorem every_mixed_byte_keeps_stack {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolExecution.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolExecution.Action)}
    (run : (byteSystem config (Targets.MixedByteOrigin redSources)).MTr [] actions after) :
    ByteFlows.Safe (fun _ => StackInvariant config layout) after :=
  Targets.mixed_bytes_keep_protection config layout redSources mixed_local_conditions
    red_sources_checked run

theorem every_mixed_black_byte_has_actual_layer_order {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolExecution.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolExecution.Action)}
    (run : (byteSystem config (Targets.MixedByteOrigin redSources)).MTr [] actions after)
    (packet : ByteFlows.Carrier MultiProtocolExecution.State Byte) (member : packet ∈ after)
    (ready : packet.state.phase = .ready) (black : packet.state.port ∈ blackPorts)
    (byte : Byte) (contains : byte ∈ packet.bytes) :
    packet.state.frame.body.protectionLayers = [2, 1] ∧
    ∃ start labels, Targets.MixedByteOrigin redSources start byte ∧
      (byteLineage config).MTr start labels packet.state ∧
      ByteOrderedEncryptions config 1 2 start labels packet.state :=
  Targets.every_mixed_black_byte_has_ordered_encryptions config layout redSources blackPorts
    mixed_local_conditions red_sources_checked black_ports_checked
    (fun port => outer_port_shapes _ (Execution.port_at_member_or_default ports port))
    run packet member ready black byte contains

end TDN.Imported.PairingMacsecMacsecStandalone

namespace TDN.Imported.PairingInnerMacsecOuterIpsec
open MultiProtocolExecution

theorem every_mixed_byte_keeps_stack {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolExecution.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolExecution.Action)}
    (run : (byteSystem config (Targets.MixedByteOrigin redSources)).MTr [] actions after) :
    ByteFlows.Safe (fun _ => StackInvariant config layout) after :=
  Targets.mixed_bytes_keep_protection config layout redSources mixed_local_conditions
    red_sources_checked run

theorem every_mixed_black_byte_has_actual_layer_order {Byte : Type}
    {after : List (ByteFlows.Carrier MultiProtocolExecution.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolExecution.Action)}
    (run : (byteSystem config (Targets.MixedByteOrigin redSources)).MTr [] actions after)
    (packet : ByteFlows.Carrier MultiProtocolExecution.State Byte) (member : packet ∈ after)
    (ready : packet.state.phase = .ready) (black : packet.state.port ∈ blackPorts)
    (byte : Byte) (contains : byte ∈ packet.bytes) :
    packet.state.frame.body.protectionLayers = [2, 1] ∧
    ∃ start labels, Targets.MixedByteOrigin redSources start byte ∧
      (byteLineage config).MTr start labels packet.state ∧
      ByteOrderedEncryptions config 1 2 start labels packet.state :=
  Targets.every_mixed_black_byte_has_ordered_encryptions config layout redSources blackPorts
    mixed_local_conditions red_sources_checked black_ports_checked
    (fun port => outer_port_shapes _ (Execution.port_at_member_or_default ports port))
    run packet member ready black byte contains

end TDN.Imported.PairingInnerMacsecOuterIpsec

namespace TDN.Imported.PairingIpsecIpsecIntegrated.Forward
open MultiProtocolExecution

theorem positive_three_byte_delivery :
    (byteSystem config (Targets.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState39, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Targets.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Targets.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Imported.PairingIpsecIpsecIntegrated.Forward

namespace TDN.Imported.PairingIpsecIpsecIntegrated.Reverse
open MultiProtocolExecution

theorem positive_three_byte_delivery :
    (byteSystem config (Targets.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState39, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Targets.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Targets.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Imported.PairingIpsecIpsecIntegrated.Reverse

namespace TDN.Imported.PairingIpsecMacsecIntegrated.Forward
open MultiProtocolExecution

theorem positive_three_byte_delivery :
    (byteSystem config (Targets.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState32, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Targets.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Targets.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Imported.PairingIpsecMacsecIntegrated.Forward

namespace TDN.Imported.PairingIpsecMacsecIntegrated.Reverse
open MultiProtocolExecution

theorem positive_three_byte_delivery :
    (byteSystem config (Targets.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState32, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Targets.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Targets.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Imported.PairingIpsecMacsecIntegrated.Reverse

namespace TDN.Imported.PairingMacsecIpsecIntegrated.Forward
open MultiProtocolExecution

theorem positive_three_byte_delivery :
    (byteSystem config (Targets.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState41, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Targets.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Targets.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Imported.PairingMacsecIpsecIntegrated.Forward

namespace TDN.Imported.PairingMacsecIpsecIntegrated.Reverse
open MultiProtocolExecution

theorem positive_three_byte_delivery :
    (byteSystem config (Targets.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState41, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Targets.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Targets.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Imported.PairingMacsecIpsecIntegrated.Reverse

namespace TDN.Imported.PairingMacsecIpsecStandalone.Forward
open MultiProtocolExecution

theorem positive_three_byte_delivery :
    (byteSystem config (Targets.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState51, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Targets.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Targets.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Imported.PairingMacsecIpsecStandalone.Forward

namespace TDN.Imported.PairingMacsecIpsecStandalone.Reverse
open MultiProtocolExecution

theorem positive_three_byte_delivery :
    (byteSystem config (Targets.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState51, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Targets.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Targets.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Imported.PairingMacsecIpsecStandalone.Reverse

namespace TDN.Imported.PairingMacsecMacsecIntegrated.Forward
open MultiProtocolExecution

theorem positive_three_byte_delivery :
    (byteSystem config (Targets.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState34, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Targets.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Targets.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Imported.PairingMacsecMacsecIntegrated.Forward

namespace TDN.Imported.PairingMacsecMacsecIntegrated.Reverse
open MultiProtocolExecution

theorem positive_three_byte_delivery :
    (byteSystem config (Targets.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState34, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Targets.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Targets.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Imported.PairingMacsecMacsecIntegrated.Reverse

namespace TDN.Imported.PairingMacsecMacsecStandalone.Forward
open MultiProtocolExecution

theorem positive_three_byte_delivery :
    (byteSystem config (Targets.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState44, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Targets.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Targets.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Imported.PairingMacsecMacsecStandalone.Forward

namespace TDN.Imported.PairingMacsecMacsecStandalone.Reverse
open MultiProtocolExecution

theorem positive_three_byte_delivery :
    (byteSystem config (Targets.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState44, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Targets.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Targets.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Imported.PairingMacsecMacsecStandalone.Reverse

namespace TDN.Imported.PairingInnerMacsecOuterIpsec.ForwardVLAN0
open MultiProtocolExecution

theorem positive_three_byte_delivery :
    (byteSystem config (Targets.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState30, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Targets.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Targets.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Imported.PairingInnerMacsecOuterIpsec.ForwardVLAN0

namespace TDN.Imported.PairingInnerMacsecOuterIpsec.ForwardVLAN1
open MultiProtocolExecution

theorem positive_three_byte_delivery :
    (byteSystem config (Targets.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState30, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Targets.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Targets.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Imported.PairingInnerMacsecOuterIpsec.ForwardVLAN1

namespace TDN.Imported.PairingInnerMacsecOuterIpsec.ForwardVLAN2
open MultiProtocolExecution

theorem positive_three_byte_delivery :
    (byteSystem config (Targets.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState30, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Targets.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Targets.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Imported.PairingInnerMacsecOuterIpsec.ForwardVLAN2

namespace TDN.Imported.PairingInnerMacsecOuterIpsec.ReverseVLAN0
open MultiProtocolExecution

theorem positive_three_byte_delivery :
    (byteSystem config (Targets.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState30, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Targets.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Targets.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Imported.PairingInnerMacsecOuterIpsec.ReverseVLAN0

namespace TDN.Imported.PairingInnerMacsecOuterIpsec.ReverseVLAN1
open MultiProtocolExecution

theorem positive_three_byte_delivery :
    (byteSystem config (Targets.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState30, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Targets.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Targets.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Imported.PairingInnerMacsecOuterIpsec.ReverseVLAN1

namespace TDN.Imported.PairingInnerMacsecOuterIpsec.ReverseVLAN2
open MultiProtocolExecution

theorem positive_three_byte_delivery :
    (byteSystem config (Targets.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨usefulState30, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Targets.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Targets.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end TDN.Imported.PairingInnerMacsecOuterIpsec.ReverseVLAN2
