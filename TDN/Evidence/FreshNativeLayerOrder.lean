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

lemma outer_port_shapes : ∀ port ∈ ({} : PortData) :: ports,
    port.stack.head? = some 2 → port.stack = [2, 1] := by
  unfold ports
  decide

theorem actual_inner_encryption_precedes_outer {start finish : Execution.State}
    {actions : List Action} (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.phase = .ready) (black : finish.port ∈ blackPorts) :
    OrderedEncryptions config 1 2 start actions finish :=
  Targets.protected_black_execution_applies_layers_in_order config layout redSources blackPorts
    local_stack_conditions sources_checked black_ports_checked
    (fun port => outer_port_shapes _ (port_at_member_or_default ports port))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : Execution.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState Execution.State Header Byte}
    {actions : List (Option Action)}
    (origin : Targets.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.phase = .ready) (black : finish.logical.port ∈ blackPorts) :
    finish.logical.frame.tags = [2, 1] :=
  Targets.fragmented_black_transmission_keeps_layers config layout redSources blackPorts encode
    local_stack_conditions sources_checked black_ports_checked origin run ready black

end TDN.Imported.FreshSharedExecution

namespace TDN.Imported.FreshBaselineExecution
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_port_shapes : ∀ port ∈ ({} : PortData) :: ports,
    port.stack.head? = some 2 → port.stack = [2, 1] := by
  unfold ports
  decide

theorem actual_inner_encryption_precedes_outer {start finish : Execution.State}
    {actions : List Action} (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.phase = .ready) (black : finish.port ∈ blackPorts) :
    OrderedEncryptions config 1 2 start actions finish :=
  Targets.protected_black_execution_applies_layers_in_order config layout redSources blackPorts
    local_stack_conditions sources_checked black_ports_checked
    (fun port => outer_port_shapes _ (port_at_member_or_default ports port))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : Execution.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState Execution.State Header Byte}
    {actions : List (Option Action)}
    (origin : Targets.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.phase = .ready) (black : finish.logical.port ∈ blackPorts) :
    finish.logical.frame.tags = [2, 1] :=
  Targets.fragmented_black_transmission_keeps_layers config layout redSources blackPorts encode
    local_stack_conditions sources_checked black_ports_checked origin run ready black

end TDN.Imported.FreshBaselineExecution

namespace TDN.Imported.Family666
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_port_shapes : ∀ port ∈ ({} : PortData) :: ports,
    port.stack.head? = some 2 → port.stack = [2, 1] := by
  unfold ports
  decide

theorem actual_inner_encryption_precedes_outer {start finish : Execution.State}
    {actions : List Action} (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.phase = .ready) (black : finish.port ∈ blackPorts) :
    OrderedEncryptions config 1 2 start actions finish :=
  Targets.protected_black_execution_applies_layers_in_order config layout redSources blackPorts
    local_stack_conditions sources_checked black_ports_checked
    (fun port => outer_port_shapes _ (port_at_member_or_default ports port))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : Execution.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState Execution.State Header Byte}
    {actions : List (Option Action)}
    (origin : Targets.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.phase = .ready) (black : finish.logical.port ∈ blackPorts) :
    finish.logical.frame.tags = [2, 1] :=
  Targets.fragmented_black_transmission_keeps_layers config layout redSources blackPorts encode
    local_stack_conditions sources_checked black_ports_checked origin run ready black

end TDN.Imported.Family666

namespace TDN.Imported.Family444
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_port_shapes : ∀ port ∈ ({} : PortData) :: ports,
    port.stack.head? = some 2 → port.stack = [2, 1] := by
  unfold ports
  decide

theorem actual_inner_encryption_precedes_outer {start finish : Execution.State}
    {actions : List Action} (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.phase = .ready) (black : finish.port ∈ blackPorts) :
    OrderedEncryptions config 1 2 start actions finish :=
  Targets.protected_black_execution_applies_layers_in_order config layout redSources blackPorts
    local_stack_conditions sources_checked black_ports_checked
    (fun port => outer_port_shapes _ (port_at_member_or_default ports port))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : Execution.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState Execution.State Header Byte}
    {actions : List (Option Action)}
    (origin : Targets.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.phase = .ready) (black : finish.logical.port ∈ blackPorts) :
    finish.logical.frame.tags = [2, 1] :=
  Targets.fragmented_black_transmission_keeps_layers config layout redSources blackPorts encode
    local_stack_conditions sources_checked black_ports_checked origin run ready black

end TDN.Imported.Family444

namespace TDN.Imported.Family446
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_port_shapes : ∀ port ∈ ({} : PortData) :: ports,
    port.stack.head? = some 2 → port.stack = [2, 1] := by
  unfold ports
  decide

theorem actual_inner_encryption_precedes_outer {start finish : Execution.State}
    {actions : List Action} (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.phase = .ready) (black : finish.port ∈ blackPorts) :
    OrderedEncryptions config 1 2 start actions finish :=
  Targets.protected_black_execution_applies_layers_in_order config layout redSources blackPorts
    local_stack_conditions sources_checked black_ports_checked
    (fun port => outer_port_shapes _ (port_at_member_or_default ports port))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : Execution.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState Execution.State Header Byte}
    {actions : List (Option Action)}
    (origin : Targets.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.phase = .ready) (black : finish.logical.port ∈ blackPorts) :
    finish.logical.frame.tags = [2, 1] :=
  Targets.fragmented_black_transmission_keeps_layers config layout redSources blackPorts encode
    local_stack_conditions sources_checked black_ports_checked origin run ready black

end TDN.Imported.Family446

namespace TDN.Imported.Family464
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_port_shapes : ∀ port ∈ ({} : PortData) :: ports,
    port.stack.head? = some 2 → port.stack = [2, 1] := by
  unfold ports
  decide

theorem actual_inner_encryption_precedes_outer {start finish : Execution.State}
    {actions : List Action} (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.phase = .ready) (black : finish.port ∈ blackPorts) :
    OrderedEncryptions config 1 2 start actions finish :=
  Targets.protected_black_execution_applies_layers_in_order config layout redSources blackPorts
    local_stack_conditions sources_checked black_ports_checked
    (fun port => outer_port_shapes _ (port_at_member_or_default ports port))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : Execution.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState Execution.State Header Byte}
    {actions : List (Option Action)}
    (origin : Targets.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.phase = .ready) (black : finish.logical.port ∈ blackPorts) :
    finish.logical.frame.tags = [2, 1] :=
  Targets.fragmented_black_transmission_keeps_layers config layout redSources blackPorts encode
    local_stack_conditions sources_checked black_ports_checked origin run ready black

end TDN.Imported.Family464

namespace TDN.Imported.Family466
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_port_shapes : ∀ port ∈ ({} : PortData) :: ports,
    port.stack.head? = some 2 → port.stack = [2, 1] := by
  unfold ports
  decide

theorem actual_inner_encryption_precedes_outer {start finish : Execution.State}
    {actions : List Action} (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.phase = .ready) (black : finish.port ∈ blackPorts) :
    OrderedEncryptions config 1 2 start actions finish :=
  Targets.protected_black_execution_applies_layers_in_order config layout redSources blackPorts
    local_stack_conditions sources_checked black_ports_checked
    (fun port => outer_port_shapes _ (port_at_member_or_default ports port))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : Execution.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState Execution.State Header Byte}
    {actions : List (Option Action)}
    (origin : Targets.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.phase = .ready) (black : finish.logical.port ∈ blackPorts) :
    finish.logical.frame.tags = [2, 1] :=
  Targets.fragmented_black_transmission_keeps_layers config layout redSources blackPorts encode
    local_stack_conditions sources_checked black_ports_checked origin run ready black

end TDN.Imported.Family466

namespace TDN.Imported.Family644
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_port_shapes : ∀ port ∈ ({} : PortData) :: ports,
    port.stack.head? = some 2 → port.stack = [2, 1] := by
  unfold ports
  decide

theorem actual_inner_encryption_precedes_outer {start finish : Execution.State}
    {actions : List Action} (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.phase = .ready) (black : finish.port ∈ blackPorts) :
    OrderedEncryptions config 1 2 start actions finish :=
  Targets.protected_black_execution_applies_layers_in_order config layout redSources blackPorts
    local_stack_conditions sources_checked black_ports_checked
    (fun port => outer_port_shapes _ (port_at_member_or_default ports port))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : Execution.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState Execution.State Header Byte}
    {actions : List (Option Action)}
    (origin : Targets.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.phase = .ready) (black : finish.logical.port ∈ blackPorts) :
    finish.logical.frame.tags = [2, 1] :=
  Targets.fragmented_black_transmission_keeps_layers config layout redSources blackPorts encode
    local_stack_conditions sources_checked black_ports_checked origin run ready black

end TDN.Imported.Family644

namespace TDN.Imported.Family646
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_port_shapes : ∀ port ∈ ({} : PortData) :: ports,
    port.stack.head? = some 2 → port.stack = [2, 1] := by
  unfold ports
  decide

theorem actual_inner_encryption_precedes_outer {start finish : Execution.State}
    {actions : List Action} (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.phase = .ready) (black : finish.port ∈ blackPorts) :
    OrderedEncryptions config 1 2 start actions finish :=
  Targets.protected_black_execution_applies_layers_in_order config layout redSources blackPorts
    local_stack_conditions sources_checked black_ports_checked
    (fun port => outer_port_shapes _ (port_at_member_or_default ports port))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : Execution.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState Execution.State Header Byte}
    {actions : List (Option Action)}
    (origin : Targets.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.phase = .ready) (black : finish.logical.port ∈ blackPorts) :
    finish.logical.frame.tags = [2, 1] :=
  Targets.fragmented_black_transmission_keeps_layers config layout redSources blackPorts encode
    local_stack_conditions sources_checked black_ports_checked origin run ready black

end TDN.Imported.Family646

namespace TDN.Imported.Family664
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma outer_port_shapes : ∀ port ∈ ({} : PortData) :: ports,
    port.stack.head? = some 2 → port.stack = [2, 1] := by
  unfold ports
  decide

theorem actual_inner_encryption_precedes_outer {start finish : Execution.State}
    {actions : List Action} (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (lts config).MTr start actions finish)
    (ready : finish.phase = .ready) (black : finish.port ∈ blackPorts) :
    OrderedEncryptions config 1 2 start actions finish :=
  Targets.protected_black_execution_applies_layers_in_order config layout redSources blackPorts
    local_stack_conditions sources_checked black_ports_checked
    (fun port => outer_port_shapes _ (port_at_member_or_default ports port))
    origin run ready black

theorem fragmented_transmission_has_both_layers {Header Byte : Type} [DecidableEq Header]
    (encode : Execution.State → Fragmentation.Datagram Header Byte)
    {start finish : Fragmentation.SegmentedState Execution.State Header Byte}
    {actions : List (Option Action)}
    (origin : Targets.RedPayloadOrigin config redSources start.logical)
    (run : (Fragmentation.segmented (lts config) encode).MTr start actions finish)
    (ready : finish.logical.phase = .ready) (black : finish.logical.port ∈ blackPorts) :
    finish.logical.frame.tags = [2, 1] :=
  Targets.fragmented_black_transmission_keeps_layers config layout redSources blackPorts encode
    local_stack_conditions sources_checked black_ports_checked origin run ready black

end TDN.Imported.Family664
