import TDN.Deployments.DualStack_RedV6_GrayV6_BlackV4
import TDN.Deployments.DualStack_RedV6_GrayV4_BlackV6
import TDN.Deployments.DualStack_RedV6_GrayV4_BlackV4
import TDN.Deployments.DualStack_RedV4_GrayV6_BlackV6
import TDN.Deployments.DualStack_RedV4_GrayV6_BlackV4
import TDN.Deployments.DualStack_RedV4_GrayV4_BlackV6
import TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4
import TDN.Deployments.ProfileShared_DataPlane
import TDN.Deployments.ProfileBaseline_DataPlane
import TDN.Deployments.DualStack_RedV6_GrayV6_BlackV6

namespace TDN.Deployments.ProfileShared_DataPlane
open DataPlaneForwarding
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_iface_shapes : ∀ iface ∈ ({} : IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces
  decide

theorem actual_inner_encryption_precedes_outer {start finish : DataPlaneForwarding.State}
    {actions : List Action} (origin : Requirements.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .egressReady) (black : finish.iface ∈ blackIfaces) :
    OrderedEncryptions config 1 2 start actions finish :=
  Requirements.protected_black_forwarding_applies_layers_in_order config expectedEncapStack redSources blackIfaces
    local_stack_conditions sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (iface_at_member_or_default ifaces iface))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : DataPlaneForwarding.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState DataPlaneForwarding.State Header Byte}
    {actions : List (Option Action)}
    (origin : Requirements.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.datapathStage = .egressReady) (black : finish.logical.iface ∈ blackIfaces) :
    finish.logical.frame.encapLayerIds = [2, 1] :=
  Requirements.fragmented_black_transmission_keeps_layers config expectedEncapStack redSources blackIfaces encode
    local_stack_conditions sources_checked black_ifaces_checked origin run ready black

end TDN.Deployments.ProfileShared_DataPlane

namespace TDN.Deployments.ProfileBaseline_DataPlane
open DataPlaneForwarding
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_iface_shapes : ∀ iface ∈ ({} : IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces
  decide

theorem actual_inner_encryption_precedes_outer {start finish : DataPlaneForwarding.State}
    {actions : List Action} (origin : Requirements.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .egressReady) (black : finish.iface ∈ blackIfaces) :
    OrderedEncryptions config 1 2 start actions finish :=
  Requirements.protected_black_forwarding_applies_layers_in_order config expectedEncapStack redSources blackIfaces
    local_stack_conditions sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (iface_at_member_or_default ifaces iface))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : DataPlaneForwarding.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState DataPlaneForwarding.State Header Byte}
    {actions : List (Option Action)}
    (origin : Requirements.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.datapathStage = .egressReady) (black : finish.logical.iface ∈ blackIfaces) :
    finish.logical.frame.encapLayerIds = [2, 1] :=
  Requirements.fragmented_black_transmission_keeps_layers config expectedEncapStack redSources blackIfaces encode
    local_stack_conditions sources_checked black_ifaces_checked origin run ready black

end TDN.Deployments.ProfileBaseline_DataPlane

namespace TDN.Deployments.DualStack_RedV6_GrayV6_BlackV6
open DataPlaneForwarding
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_iface_shapes : ∀ iface ∈ ({} : IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces
  decide

theorem actual_inner_encryption_precedes_outer {start finish : DataPlaneForwarding.State}
    {actions : List Action} (origin : Requirements.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .egressReady) (black : finish.iface ∈ blackIfaces) :
    OrderedEncryptions config 1 2 start actions finish :=
  Requirements.protected_black_forwarding_applies_layers_in_order config expectedEncapStack redSources blackIfaces
    local_stack_conditions sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (iface_at_member_or_default ifaces iface))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : DataPlaneForwarding.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState DataPlaneForwarding.State Header Byte}
    {actions : List (Option Action)}
    (origin : Requirements.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.datapathStage = .egressReady) (black : finish.logical.iface ∈ blackIfaces) :
    finish.logical.frame.encapLayerIds = [2, 1] :=
  Requirements.fragmented_black_transmission_keeps_layers config expectedEncapStack redSources blackIfaces encode
    local_stack_conditions sources_checked black_ifaces_checked origin run ready black

end TDN.Deployments.DualStack_RedV6_GrayV6_BlackV6

namespace TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4
open DataPlaneForwarding
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_iface_shapes : ∀ iface ∈ ({} : IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces
  decide

theorem actual_inner_encryption_precedes_outer {start finish : DataPlaneForwarding.State}
    {actions : List Action} (origin : Requirements.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .egressReady) (black : finish.iface ∈ blackIfaces) :
    OrderedEncryptions config 1 2 start actions finish :=
  Requirements.protected_black_forwarding_applies_layers_in_order config expectedEncapStack redSources blackIfaces
    local_stack_conditions sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (iface_at_member_or_default ifaces iface))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : DataPlaneForwarding.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState DataPlaneForwarding.State Header Byte}
    {actions : List (Option Action)}
    (origin : Requirements.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.datapathStage = .egressReady) (black : finish.logical.iface ∈ blackIfaces) :
    finish.logical.frame.encapLayerIds = [2, 1] :=
  Requirements.fragmented_black_transmission_keeps_layers config expectedEncapStack redSources blackIfaces encode
    local_stack_conditions sources_checked black_ifaces_checked origin run ready black

end TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4

namespace TDN.Deployments.DualStack_RedV4_GrayV4_BlackV6
open DataPlaneForwarding
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_iface_shapes : ∀ iface ∈ ({} : IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces
  decide

theorem actual_inner_encryption_precedes_outer {start finish : DataPlaneForwarding.State}
    {actions : List Action} (origin : Requirements.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .egressReady) (black : finish.iface ∈ blackIfaces) :
    OrderedEncryptions config 1 2 start actions finish :=
  Requirements.protected_black_forwarding_applies_layers_in_order config expectedEncapStack redSources blackIfaces
    local_stack_conditions sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (iface_at_member_or_default ifaces iface))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : DataPlaneForwarding.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState DataPlaneForwarding.State Header Byte}
    {actions : List (Option Action)}
    (origin : Requirements.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.datapathStage = .egressReady) (black : finish.logical.iface ∈ blackIfaces) :
    finish.logical.frame.encapLayerIds = [2, 1] :=
  Requirements.fragmented_black_transmission_keeps_layers config expectedEncapStack redSources blackIfaces encode
    local_stack_conditions sources_checked black_ifaces_checked origin run ready black

end TDN.Deployments.DualStack_RedV4_GrayV4_BlackV6

namespace TDN.Deployments.DualStack_RedV4_GrayV6_BlackV4
open DataPlaneForwarding
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_iface_shapes : ∀ iface ∈ ({} : IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces
  decide

theorem actual_inner_encryption_precedes_outer {start finish : DataPlaneForwarding.State}
    {actions : List Action} (origin : Requirements.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .egressReady) (black : finish.iface ∈ blackIfaces) :
    OrderedEncryptions config 1 2 start actions finish :=
  Requirements.protected_black_forwarding_applies_layers_in_order config expectedEncapStack redSources blackIfaces
    local_stack_conditions sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (iface_at_member_or_default ifaces iface))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : DataPlaneForwarding.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState DataPlaneForwarding.State Header Byte}
    {actions : List (Option Action)}
    (origin : Requirements.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.datapathStage = .egressReady) (black : finish.logical.iface ∈ blackIfaces) :
    finish.logical.frame.encapLayerIds = [2, 1] :=
  Requirements.fragmented_black_transmission_keeps_layers config expectedEncapStack redSources blackIfaces encode
    local_stack_conditions sources_checked black_ifaces_checked origin run ready black

end TDN.Deployments.DualStack_RedV4_GrayV6_BlackV4

namespace TDN.Deployments.DualStack_RedV4_GrayV6_BlackV6
open DataPlaneForwarding
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_iface_shapes : ∀ iface ∈ ({} : IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces
  decide

theorem actual_inner_encryption_precedes_outer {start finish : DataPlaneForwarding.State}
    {actions : List Action} (origin : Requirements.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .egressReady) (black : finish.iface ∈ blackIfaces) :
    OrderedEncryptions config 1 2 start actions finish :=
  Requirements.protected_black_forwarding_applies_layers_in_order config expectedEncapStack redSources blackIfaces
    local_stack_conditions sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (iface_at_member_or_default ifaces iface))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : DataPlaneForwarding.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState DataPlaneForwarding.State Header Byte}
    {actions : List (Option Action)}
    (origin : Requirements.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.datapathStage = .egressReady) (black : finish.logical.iface ∈ blackIfaces) :
    finish.logical.frame.encapLayerIds = [2, 1] :=
  Requirements.fragmented_black_transmission_keeps_layers config expectedEncapStack redSources blackIfaces encode
    local_stack_conditions sources_checked black_ifaces_checked origin run ready black

end TDN.Deployments.DualStack_RedV4_GrayV6_BlackV6

namespace TDN.Deployments.DualStack_RedV6_GrayV4_BlackV4
open DataPlaneForwarding
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_iface_shapes : ∀ iface ∈ ({} : IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces
  decide

theorem actual_inner_encryption_precedes_outer {start finish : DataPlaneForwarding.State}
    {actions : List Action} (origin : Requirements.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .egressReady) (black : finish.iface ∈ blackIfaces) :
    OrderedEncryptions config 1 2 start actions finish :=
  Requirements.protected_black_forwarding_applies_layers_in_order config expectedEncapStack redSources blackIfaces
    local_stack_conditions sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (iface_at_member_or_default ifaces iface))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : DataPlaneForwarding.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState DataPlaneForwarding.State Header Byte}
    {actions : List (Option Action)}
    (origin : Requirements.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.datapathStage = .egressReady) (black : finish.logical.iface ∈ blackIfaces) :
    finish.logical.frame.encapLayerIds = [2, 1] :=
  Requirements.fragmented_black_transmission_keeps_layers config expectedEncapStack redSources blackIfaces encode
    local_stack_conditions sources_checked black_ifaces_checked origin run ready black

end TDN.Deployments.DualStack_RedV6_GrayV4_BlackV4

namespace TDN.Deployments.DualStack_RedV6_GrayV4_BlackV6
open DataPlaneForwarding
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_iface_shapes : ∀ iface ∈ ({} : IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces
  decide

theorem actual_inner_encryption_precedes_outer {start finish : DataPlaneForwarding.State}
    {actions : List Action} (origin : Requirements.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .egressReady) (black : finish.iface ∈ blackIfaces) :
    OrderedEncryptions config 1 2 start actions finish :=
  Requirements.protected_black_forwarding_applies_layers_in_order config expectedEncapStack redSources blackIfaces
    local_stack_conditions sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (iface_at_member_or_default ifaces iface))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : DataPlaneForwarding.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState DataPlaneForwarding.State Header Byte}
    {actions : List (Option Action)}
    (origin : Requirements.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.datapathStage = .egressReady) (black : finish.logical.iface ∈ blackIfaces) :
    finish.logical.frame.encapLayerIds = [2, 1] :=
  Requirements.fragmented_black_transmission_keeps_layers config expectedEncapStack redSources blackIfaces encode
    local_stack_conditions sources_checked black_ifaces_checked origin run ready black

end TDN.Deployments.DualStack_RedV6_GrayV4_BlackV6

namespace TDN.Deployments.DualStack_RedV6_GrayV6_BlackV4
open DataPlaneForwarding
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_iface_shapes : ∀ iface ∈ ({} : IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces
  decide

theorem actual_inner_encryption_precedes_outer {start finish : DataPlaneForwarding.State}
    {actions : List Action} (origin : Requirements.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .egressReady) (black : finish.iface ∈ blackIfaces) :
    OrderedEncryptions config 1 2 start actions finish :=
  Requirements.protected_black_forwarding_applies_layers_in_order config expectedEncapStack redSources blackIfaces
    local_stack_conditions sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (iface_at_member_or_default ifaces iface))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : DataPlaneForwarding.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState DataPlaneForwarding.State Header Byte}
    {actions : List (Option Action)}
    (origin : Requirements.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.datapathStage = .egressReady) (black : finish.logical.iface ∈ blackIfaces) :
    finish.logical.frame.encapLayerIds = [2, 1] :=
  Requirements.fragmented_black_transmission_keeps_layers config expectedEncapStack redSources blackIfaces encode
    local_stack_conditions sources_checked black_ifaces_checked origin run ready black

end TDN.Deployments.DualStack_RedV6_GrayV6_BlackV4
