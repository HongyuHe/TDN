import TDN.Targets.DistributedPacketExecution
import TDN.Evidence.FreshNativeLayerOrder

namespace TDN.Imported.FreshSharedExecution

/-- The same checked network conditions cover independently moving fragment pieces. -/
theorem each_fragment_at_black_retains_protection {Byte : Type}
    (encodedBytes : Execution.Frame → List Byte)
    {start : Execution.State}
    {located : List (Execution.State × Fragmentation.Fragment Execution.FragmentDescriptor Byte)}
    {actions : List (Option Execution.Action)}
    (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (Fragmentation.distributed (Execution.lts config)
      (Execution.encodeForFragmentation encodedBytes)).MTr (.whole start) actions (.pieces located)) :
    ∀ entry ∈ located, entry.1.phase = .ready → entry.1.port ∈ blackPorts →
      entry.2.header.layers = [2, 1] ∧
      entry.2.header.payload = start.frame.payload ∧
      entry.2.header.originDomain = start.frame.originDomain :=
  Targets.every_distributed_black_piece_is_double_protected config layout redSources blackPorts
    encodedBytes local_stack_conditions sources_checked black_ports_checked origin run

end TDN.Imported.FreshSharedExecution


namespace TDN.Imported.FreshBaselineExecution

/-- The same checked network conditions cover independently moving fragment pieces. -/
theorem each_fragment_at_black_retains_protection {Byte : Type}
    (encodedBytes : Execution.Frame → List Byte)
    {start : Execution.State}
    {located : List (Execution.State × Fragmentation.Fragment Execution.FragmentDescriptor Byte)}
    {actions : List (Option Execution.Action)}
    (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (Fragmentation.distributed (Execution.lts config)
      (Execution.encodeForFragmentation encodedBytes)).MTr (.whole start) actions (.pieces located)) :
    ∀ entry ∈ located, entry.1.phase = .ready → entry.1.port ∈ blackPorts →
      entry.2.header.layers = [2, 1] ∧
      entry.2.header.payload = start.frame.payload ∧
      entry.2.header.originDomain = start.frame.originDomain :=
  Targets.every_distributed_black_piece_is_double_protected config layout redSources blackPorts
    encodedBytes local_stack_conditions sources_checked black_ports_checked origin run

end TDN.Imported.FreshBaselineExecution


namespace TDN.Imported.Family444

/-- The same checked network conditions cover independently moving fragment pieces. -/
theorem each_fragment_at_black_retains_protection {Byte : Type}
    (encodedBytes : Execution.Frame → List Byte)
    {start : Execution.State}
    {located : List (Execution.State × Fragmentation.Fragment Execution.FragmentDescriptor Byte)}
    {actions : List (Option Execution.Action)}
    (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (Fragmentation.distributed (Execution.lts config)
      (Execution.encodeForFragmentation encodedBytes)).MTr (.whole start) actions (.pieces located)) :
    ∀ entry ∈ located, entry.1.phase = .ready → entry.1.port ∈ blackPorts →
      entry.2.header.layers = [2, 1] ∧
      entry.2.header.payload = start.frame.payload ∧
      entry.2.header.originDomain = start.frame.originDomain :=
  Targets.every_distributed_black_piece_is_double_protected config layout redSources blackPorts
    encodedBytes local_stack_conditions sources_checked black_ports_checked origin run

end TDN.Imported.Family444


namespace TDN.Imported.Family446

/-- The same checked network conditions cover independently moving fragment pieces. -/
theorem each_fragment_at_black_retains_protection {Byte : Type}
    (encodedBytes : Execution.Frame → List Byte)
    {start : Execution.State}
    {located : List (Execution.State × Fragmentation.Fragment Execution.FragmentDescriptor Byte)}
    {actions : List (Option Execution.Action)}
    (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (Fragmentation.distributed (Execution.lts config)
      (Execution.encodeForFragmentation encodedBytes)).MTr (.whole start) actions (.pieces located)) :
    ∀ entry ∈ located, entry.1.phase = .ready → entry.1.port ∈ blackPorts →
      entry.2.header.layers = [2, 1] ∧
      entry.2.header.payload = start.frame.payload ∧
      entry.2.header.originDomain = start.frame.originDomain :=
  Targets.every_distributed_black_piece_is_double_protected config layout redSources blackPorts
    encodedBytes local_stack_conditions sources_checked black_ports_checked origin run

end TDN.Imported.Family446


namespace TDN.Imported.Family464

/-- The same checked network conditions cover independently moving fragment pieces. -/
theorem each_fragment_at_black_retains_protection {Byte : Type}
    (encodedBytes : Execution.Frame → List Byte)
    {start : Execution.State}
    {located : List (Execution.State × Fragmentation.Fragment Execution.FragmentDescriptor Byte)}
    {actions : List (Option Execution.Action)}
    (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (Fragmentation.distributed (Execution.lts config)
      (Execution.encodeForFragmentation encodedBytes)).MTr (.whole start) actions (.pieces located)) :
    ∀ entry ∈ located, entry.1.phase = .ready → entry.1.port ∈ blackPorts →
      entry.2.header.layers = [2, 1] ∧
      entry.2.header.payload = start.frame.payload ∧
      entry.2.header.originDomain = start.frame.originDomain :=
  Targets.every_distributed_black_piece_is_double_protected config layout redSources blackPorts
    encodedBytes local_stack_conditions sources_checked black_ports_checked origin run

end TDN.Imported.Family464


namespace TDN.Imported.Family466

/-- The same checked network conditions cover independently moving fragment pieces. -/
theorem each_fragment_at_black_retains_protection {Byte : Type}
    (encodedBytes : Execution.Frame → List Byte)
    {start : Execution.State}
    {located : List (Execution.State × Fragmentation.Fragment Execution.FragmentDescriptor Byte)}
    {actions : List (Option Execution.Action)}
    (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (Fragmentation.distributed (Execution.lts config)
      (Execution.encodeForFragmentation encodedBytes)).MTr (.whole start) actions (.pieces located)) :
    ∀ entry ∈ located, entry.1.phase = .ready → entry.1.port ∈ blackPorts →
      entry.2.header.layers = [2, 1] ∧
      entry.2.header.payload = start.frame.payload ∧
      entry.2.header.originDomain = start.frame.originDomain :=
  Targets.every_distributed_black_piece_is_double_protected config layout redSources blackPorts
    encodedBytes local_stack_conditions sources_checked black_ports_checked origin run

end TDN.Imported.Family466


namespace TDN.Imported.Family644

/-- The same checked network conditions cover independently moving fragment pieces. -/
theorem each_fragment_at_black_retains_protection {Byte : Type}
    (encodedBytes : Execution.Frame → List Byte)
    {start : Execution.State}
    {located : List (Execution.State × Fragmentation.Fragment Execution.FragmentDescriptor Byte)}
    {actions : List (Option Execution.Action)}
    (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (Fragmentation.distributed (Execution.lts config)
      (Execution.encodeForFragmentation encodedBytes)).MTr (.whole start) actions (.pieces located)) :
    ∀ entry ∈ located, entry.1.phase = .ready → entry.1.port ∈ blackPorts →
      entry.2.header.layers = [2, 1] ∧
      entry.2.header.payload = start.frame.payload ∧
      entry.2.header.originDomain = start.frame.originDomain :=
  Targets.every_distributed_black_piece_is_double_protected config layout redSources blackPorts
    encodedBytes local_stack_conditions sources_checked black_ports_checked origin run

end TDN.Imported.Family644


namespace TDN.Imported.Family646

/-- The same checked network conditions cover independently moving fragment pieces. -/
theorem each_fragment_at_black_retains_protection {Byte : Type}
    (encodedBytes : Execution.Frame → List Byte)
    {start : Execution.State}
    {located : List (Execution.State × Fragmentation.Fragment Execution.FragmentDescriptor Byte)}
    {actions : List (Option Execution.Action)}
    (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (Fragmentation.distributed (Execution.lts config)
      (Execution.encodeForFragmentation encodedBytes)).MTr (.whole start) actions (.pieces located)) :
    ∀ entry ∈ located, entry.1.phase = .ready → entry.1.port ∈ blackPorts →
      entry.2.header.layers = [2, 1] ∧
      entry.2.header.payload = start.frame.payload ∧
      entry.2.header.originDomain = start.frame.originDomain :=
  Targets.every_distributed_black_piece_is_double_protected config layout redSources blackPorts
    encodedBytes local_stack_conditions sources_checked black_ports_checked origin run

end TDN.Imported.Family646


namespace TDN.Imported.Family664

/-- The same checked network conditions cover independently moving fragment pieces. -/
theorem each_fragment_at_black_retains_protection {Byte : Type}
    (encodedBytes : Execution.Frame → List Byte)
    {start : Execution.State}
    {located : List (Execution.State × Fragmentation.Fragment Execution.FragmentDescriptor Byte)}
    {actions : List (Option Execution.Action)}
    (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (Fragmentation.distributed (Execution.lts config)
      (Execution.encodeForFragmentation encodedBytes)).MTr (.whole start) actions (.pieces located)) :
    ∀ entry ∈ located, entry.1.phase = .ready → entry.1.port ∈ blackPorts →
      entry.2.header.layers = [2, 1] ∧
      entry.2.header.payload = start.frame.payload ∧
      entry.2.header.originDomain = start.frame.originDomain :=
  Targets.every_distributed_black_piece_is_double_protected config layout redSources blackPorts
    encodedBytes local_stack_conditions sources_checked black_ports_checked origin run

end TDN.Imported.Family664


namespace TDN.Imported.Family666

/-- The same checked network conditions cover independently moving fragment pieces. -/
theorem each_fragment_at_black_retains_protection {Byte : Type}
    (encodedBytes : Execution.Frame → List Byte)
    {start : Execution.State}
    {located : List (Execution.State × Fragmentation.Fragment Execution.FragmentDescriptor Byte)}
    {actions : List (Option Execution.Action)}
    (origin : Targets.RedPayloadOrigin config redSources start)
    (run : (Fragmentation.distributed (Execution.lts config)
      (Execution.encodeForFragmentation encodedBytes)).MTr (.whole start) actions (.pieces located)) :
    ∀ entry ∈ located, entry.1.phase = .ready → entry.1.port ∈ blackPorts →
      entry.2.header.layers = [2, 1] ∧
      entry.2.header.payload = start.frame.payload ∧
      entry.2.header.originDomain = start.frame.originDomain :=
  Targets.every_distributed_black_piece_is_double_protected config layout redSources blackPorts
    encodedBytes local_stack_conditions sources_checked black_ports_checked origin run

end TDN.Imported.Family666
