import TDN.Evidence.FreshFamily664
import TDN.Evidence.FreshFamily646
import TDN.Evidence.FreshFamily644
import TDN.Evidence.FreshFamily466
import TDN.Evidence.FreshFamily464
import TDN.Evidence.FreshFamily446
import TDN.Evidence.FreshFamily444
import TDN.Evidence.FreshSharedExecution
import TDN.Evidence.FreshBaselineExecution
import TDN.Evidence.FreshFamily666

namespace TDN.Imported.FreshSharedExecution
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_iface_shapes : ∀ iface ∈ ({} : IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces
  decide

theorem actual_inner_encryption_precedes_outer {start finish : Execution.State}
    {actions : List Action} (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .ready) (black : finish.iface ∈ blackIfaces) :
    OrderedEncryptions config 1 2 start actions finish :=
  Targets.protected_black_execution_applies_layers_in_order config expectedEncapStack redSources blackIfaces
    local_stack_conditions sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (iface_at_member_or_default ifaces iface))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : Execution.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState Execution.State Header Byte}
    {actions : List (Option Action)}
    (origin : Targets.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.datapathStage = .ready) (black : finish.logical.iface ∈ blackIfaces) :
    finish.logical.frame.tags = [2, 1] :=
  Targets.fragmented_black_transmission_keeps_layers config expectedEncapStack redSources blackIfaces encode
    local_stack_conditions sources_checked black_ifaces_checked origin run ready black

end TDN.Imported.FreshSharedExecution

namespace TDN.Imported.FreshBaselineExecution
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_iface_shapes : ∀ iface ∈ ({} : IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces
  decide

theorem actual_inner_encryption_precedes_outer {start finish : Execution.State}
    {actions : List Action} (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .ready) (black : finish.iface ∈ blackIfaces) :
    OrderedEncryptions config 1 2 start actions finish :=
  Targets.protected_black_execution_applies_layers_in_order config expectedEncapStack redSources blackIfaces
    local_stack_conditions sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (iface_at_member_or_default ifaces iface))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : Execution.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState Execution.State Header Byte}
    {actions : List (Option Action)}
    (origin : Targets.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.datapathStage = .ready) (black : finish.logical.iface ∈ blackIfaces) :
    finish.logical.frame.tags = [2, 1] :=
  Targets.fragmented_black_transmission_keeps_layers config expectedEncapStack redSources blackIfaces encode
    local_stack_conditions sources_checked black_ifaces_checked origin run ready black

end TDN.Imported.FreshBaselineExecution

namespace TDN.Imported.Family666
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_iface_shapes : ∀ iface ∈ ({} : IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces
  decide

theorem actual_inner_encryption_precedes_outer {start finish : Execution.State}
    {actions : List Action} (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .ready) (black : finish.iface ∈ blackIfaces) :
    OrderedEncryptions config 1 2 start actions finish :=
  Targets.protected_black_execution_applies_layers_in_order config expectedEncapStack redSources blackIfaces
    local_stack_conditions sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (iface_at_member_or_default ifaces iface))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : Execution.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState Execution.State Header Byte}
    {actions : List (Option Action)}
    (origin : Targets.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.datapathStage = .ready) (black : finish.logical.iface ∈ blackIfaces) :
    finish.logical.frame.tags = [2, 1] :=
  Targets.fragmented_black_transmission_keeps_layers config expectedEncapStack redSources blackIfaces encode
    local_stack_conditions sources_checked black_ifaces_checked origin run ready black

end TDN.Imported.Family666

namespace TDN.Imported.Family444
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_iface_shapes : ∀ iface ∈ ({} : IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces
  decide

theorem actual_inner_encryption_precedes_outer {start finish : Execution.State}
    {actions : List Action} (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .ready) (black : finish.iface ∈ blackIfaces) :
    OrderedEncryptions config 1 2 start actions finish :=
  Targets.protected_black_execution_applies_layers_in_order config expectedEncapStack redSources blackIfaces
    local_stack_conditions sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (iface_at_member_or_default ifaces iface))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : Execution.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState Execution.State Header Byte}
    {actions : List (Option Action)}
    (origin : Targets.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.datapathStage = .ready) (black : finish.logical.iface ∈ blackIfaces) :
    finish.logical.frame.tags = [2, 1] :=
  Targets.fragmented_black_transmission_keeps_layers config expectedEncapStack redSources blackIfaces encode
    local_stack_conditions sources_checked black_ifaces_checked origin run ready black

end TDN.Imported.Family444

namespace TDN.Imported.Family446
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_iface_shapes : ∀ iface ∈ ({} : IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces
  decide

theorem actual_inner_encryption_precedes_outer {start finish : Execution.State}
    {actions : List Action} (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .ready) (black : finish.iface ∈ blackIfaces) :
    OrderedEncryptions config 1 2 start actions finish :=
  Targets.protected_black_execution_applies_layers_in_order config expectedEncapStack redSources blackIfaces
    local_stack_conditions sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (iface_at_member_or_default ifaces iface))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : Execution.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState Execution.State Header Byte}
    {actions : List (Option Action)}
    (origin : Targets.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.datapathStage = .ready) (black : finish.logical.iface ∈ blackIfaces) :
    finish.logical.frame.tags = [2, 1] :=
  Targets.fragmented_black_transmission_keeps_layers config expectedEncapStack redSources blackIfaces encode
    local_stack_conditions sources_checked black_ifaces_checked origin run ready black

end TDN.Imported.Family446

namespace TDN.Imported.Family464
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_iface_shapes : ∀ iface ∈ ({} : IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces
  decide

theorem actual_inner_encryption_precedes_outer {start finish : Execution.State}
    {actions : List Action} (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .ready) (black : finish.iface ∈ blackIfaces) :
    OrderedEncryptions config 1 2 start actions finish :=
  Targets.protected_black_execution_applies_layers_in_order config expectedEncapStack redSources blackIfaces
    local_stack_conditions sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (iface_at_member_or_default ifaces iface))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : Execution.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState Execution.State Header Byte}
    {actions : List (Option Action)}
    (origin : Targets.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.datapathStage = .ready) (black : finish.logical.iface ∈ blackIfaces) :
    finish.logical.frame.tags = [2, 1] :=
  Targets.fragmented_black_transmission_keeps_layers config expectedEncapStack redSources blackIfaces encode
    local_stack_conditions sources_checked black_ifaces_checked origin run ready black

end TDN.Imported.Family464

namespace TDN.Imported.Family466
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_iface_shapes : ∀ iface ∈ ({} : IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces
  decide

theorem actual_inner_encryption_precedes_outer {start finish : Execution.State}
    {actions : List Action} (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .ready) (black : finish.iface ∈ blackIfaces) :
    OrderedEncryptions config 1 2 start actions finish :=
  Targets.protected_black_execution_applies_layers_in_order config expectedEncapStack redSources blackIfaces
    local_stack_conditions sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (iface_at_member_or_default ifaces iface))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : Execution.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState Execution.State Header Byte}
    {actions : List (Option Action)}
    (origin : Targets.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.datapathStage = .ready) (black : finish.logical.iface ∈ blackIfaces) :
    finish.logical.frame.tags = [2, 1] :=
  Targets.fragmented_black_transmission_keeps_layers config expectedEncapStack redSources blackIfaces encode
    local_stack_conditions sources_checked black_ifaces_checked origin run ready black

end TDN.Imported.Family466

namespace TDN.Imported.Family644
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_iface_shapes : ∀ iface ∈ ({} : IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces
  decide

theorem actual_inner_encryption_precedes_outer {start finish : Execution.State}
    {actions : List Action} (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .ready) (black : finish.iface ∈ blackIfaces) :
    OrderedEncryptions config 1 2 start actions finish :=
  Targets.protected_black_execution_applies_layers_in_order config expectedEncapStack redSources blackIfaces
    local_stack_conditions sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (iface_at_member_or_default ifaces iface))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : Execution.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState Execution.State Header Byte}
    {actions : List (Option Action)}
    (origin : Targets.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.datapathStage = .ready) (black : finish.logical.iface ∈ blackIfaces) :
    finish.logical.frame.tags = [2, 1] :=
  Targets.fragmented_black_transmission_keeps_layers config expectedEncapStack redSources blackIfaces encode
    local_stack_conditions sources_checked black_ifaces_checked origin run ready black

end TDN.Imported.Family644

namespace TDN.Imported.Family646
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_iface_shapes : ∀ iface ∈ ({} : IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces
  decide

theorem actual_inner_encryption_precedes_outer {start finish : Execution.State}
    {actions : List Action} (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .ready) (black : finish.iface ∈ blackIfaces) :
    OrderedEncryptions config 1 2 start actions finish :=
  Targets.protected_black_execution_applies_layers_in_order config expectedEncapStack redSources blackIfaces
    local_stack_conditions sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (iface_at_member_or_default ifaces iface))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : Execution.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState Execution.State Header Byte}
    {actions : List (Option Action)}
    (origin : Targets.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.datapathStage = .ready) (black : finish.logical.iface ∈ blackIfaces) :
    finish.logical.frame.tags = [2, 1] :=
  Targets.fragmented_black_transmission_keeps_layers config expectedEncapStack redSources blackIfaces encode
    local_stack_conditions sources_checked black_ifaces_checked origin run ready black

end TDN.Imported.Family646

namespace TDN.Imported.Family664
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_iface_shapes : ∀ iface ∈ ({} : IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces
  decide

theorem actual_inner_encryption_precedes_outer {start finish : Execution.State}
    {actions : List Action} (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .ready) (black : finish.iface ∈ blackIfaces) :
    OrderedEncryptions config 1 2 start actions finish :=
  Targets.protected_black_execution_applies_layers_in_order config expectedEncapStack redSources blackIfaces
    local_stack_conditions sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (iface_at_member_or_default ifaces iface))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : Execution.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState Execution.State Header Byte}
    {actions : List (Option Action)}
    (origin : Targets.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.datapathStage = .ready) (black : finish.logical.iface ∈ blackIfaces) :
    finish.logical.frame.tags = [2, 1] :=
  Targets.fragmented_black_transmission_keeps_layers config expectedEncapStack redSources blackIfaces encode
    local_stack_conditions sources_checked black_ifaces_checked origin run ready black

end TDN.Imported.Family664
