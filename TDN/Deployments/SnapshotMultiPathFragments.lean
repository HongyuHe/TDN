import TDN.Requirements.DistributedFragmentDoubleEncryption
import TDN.Deployments.SnapshotDeviceLayerOrder

namespace TDN.Deployments.ProfileShared_DataPlane

theorem each_fragment_at_black_retains_protection {Byte : Type}
    (encodedBytes : DataPlaneForwarding.Frame → List Byte)
    {start : DataPlaneForwarding.State}
    {located : List (DataPlaneForwarding.State × Fragmentation.Fragment DataPlaneForwarding.FragmentDescriptor Byte)}
    {actions : List (Option DataPlaneForwarding.Action)}
    (origin : Requirements.RedPayloadOrigin config redSources start)
    (run : (Fragmentation.distributed (DataPlaneForwarding.lts config)
      (DataPlaneForwarding.encodeForFragmentation encodedBytes)).MTr (.whole start) actions (.pieces located)) :
    ∀ entry ∈ located, entry.1.datapathStage = .egressReady → entry.1.iface ∈ blackIfaces →
      entry.2.header.layers = [2, 1] ∧
      entry.2.header.payload = start.frame.payload ∧
      entry.2.header.originDomain = start.frame.originDomain :=
  Requirements.every_distributed_black_piece_is_double_protected config expectedEncapStack redSources blackIfaces
    encodedBytes local_stack_conditions sources_checked black_ifaces_checked origin run

end TDN.Deployments.ProfileShared_DataPlane

namespace TDN.Deployments.ProfileBaseline_DataPlane

theorem each_fragment_at_black_retains_protection {Byte : Type}
    (encodedBytes : DataPlaneForwarding.Frame → List Byte)
    {start : DataPlaneForwarding.State}
    {located : List (DataPlaneForwarding.State × Fragmentation.Fragment DataPlaneForwarding.FragmentDescriptor Byte)}
    {actions : List (Option DataPlaneForwarding.Action)}
    (origin : Requirements.RedPayloadOrigin config redSources start)
    (run : (Fragmentation.distributed (DataPlaneForwarding.lts config)
      (DataPlaneForwarding.encodeForFragmentation encodedBytes)).MTr (.whole start) actions (.pieces located)) :
    ∀ entry ∈ located, entry.1.datapathStage = .egressReady → entry.1.iface ∈ blackIfaces →
      entry.2.header.layers = [2, 1] ∧
      entry.2.header.payload = start.frame.payload ∧
      entry.2.header.originDomain = start.frame.originDomain :=
  Requirements.every_distributed_black_piece_is_double_protected config expectedEncapStack redSources blackIfaces
    encodedBytes local_stack_conditions sources_checked black_ifaces_checked origin run

end TDN.Deployments.ProfileBaseline_DataPlane

namespace TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4

theorem each_fragment_at_black_retains_protection {Byte : Type}
    (encodedBytes : DataPlaneForwarding.Frame → List Byte)
    {start : DataPlaneForwarding.State}
    {located : List (DataPlaneForwarding.State × Fragmentation.Fragment DataPlaneForwarding.FragmentDescriptor Byte)}
    {actions : List (Option DataPlaneForwarding.Action)}
    (origin : Requirements.RedPayloadOrigin config redSources start)
    (run : (Fragmentation.distributed (DataPlaneForwarding.lts config)
      (DataPlaneForwarding.encodeForFragmentation encodedBytes)).MTr (.whole start) actions (.pieces located)) :
    ∀ entry ∈ located, entry.1.datapathStage = .egressReady → entry.1.iface ∈ blackIfaces →
      entry.2.header.layers = [2, 1] ∧
      entry.2.header.payload = start.frame.payload ∧
      entry.2.header.originDomain = start.frame.originDomain :=
  Requirements.every_distributed_black_piece_is_double_protected config expectedEncapStack redSources blackIfaces
    encodedBytes local_stack_conditions sources_checked black_ifaces_checked origin run

end TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4

namespace TDN.Deployments.DualStack_RedV4_GrayV4_BlackV6

theorem each_fragment_at_black_retains_protection {Byte : Type}
    (encodedBytes : DataPlaneForwarding.Frame → List Byte)
    {start : DataPlaneForwarding.State}
    {located : List (DataPlaneForwarding.State × Fragmentation.Fragment DataPlaneForwarding.FragmentDescriptor Byte)}
    {actions : List (Option DataPlaneForwarding.Action)}
    (origin : Requirements.RedPayloadOrigin config redSources start)
    (run : (Fragmentation.distributed (DataPlaneForwarding.lts config)
      (DataPlaneForwarding.encodeForFragmentation encodedBytes)).MTr (.whole start) actions (.pieces located)) :
    ∀ entry ∈ located, entry.1.datapathStage = .egressReady → entry.1.iface ∈ blackIfaces →
      entry.2.header.layers = [2, 1] ∧
      entry.2.header.payload = start.frame.payload ∧
      entry.2.header.originDomain = start.frame.originDomain :=
  Requirements.every_distributed_black_piece_is_double_protected config expectedEncapStack redSources blackIfaces
    encodedBytes local_stack_conditions sources_checked black_ifaces_checked origin run

end TDN.Deployments.DualStack_RedV4_GrayV4_BlackV6

namespace TDN.Deployments.DualStack_RedV4_GrayV6_BlackV4

theorem each_fragment_at_black_retains_protection {Byte : Type}
    (encodedBytes : DataPlaneForwarding.Frame → List Byte)
    {start : DataPlaneForwarding.State}
    {located : List (DataPlaneForwarding.State × Fragmentation.Fragment DataPlaneForwarding.FragmentDescriptor Byte)}
    {actions : List (Option DataPlaneForwarding.Action)}
    (origin : Requirements.RedPayloadOrigin config redSources start)
    (run : (Fragmentation.distributed (DataPlaneForwarding.lts config)
      (DataPlaneForwarding.encodeForFragmentation encodedBytes)).MTr (.whole start) actions (.pieces located)) :
    ∀ entry ∈ located, entry.1.datapathStage = .egressReady → entry.1.iface ∈ blackIfaces →
      entry.2.header.layers = [2, 1] ∧
      entry.2.header.payload = start.frame.payload ∧
      entry.2.header.originDomain = start.frame.originDomain :=
  Requirements.every_distributed_black_piece_is_double_protected config expectedEncapStack redSources blackIfaces
    encodedBytes local_stack_conditions sources_checked black_ifaces_checked origin run

end TDN.Deployments.DualStack_RedV4_GrayV6_BlackV4

namespace TDN.Deployments.DualStack_RedV4_GrayV6_BlackV6

theorem each_fragment_at_black_retains_protection {Byte : Type}
    (encodedBytes : DataPlaneForwarding.Frame → List Byte)
    {start : DataPlaneForwarding.State}
    {located : List (DataPlaneForwarding.State × Fragmentation.Fragment DataPlaneForwarding.FragmentDescriptor Byte)}
    {actions : List (Option DataPlaneForwarding.Action)}
    (origin : Requirements.RedPayloadOrigin config redSources start)
    (run : (Fragmentation.distributed (DataPlaneForwarding.lts config)
      (DataPlaneForwarding.encodeForFragmentation encodedBytes)).MTr (.whole start) actions (.pieces located)) :
    ∀ entry ∈ located, entry.1.datapathStage = .egressReady → entry.1.iface ∈ blackIfaces →
      entry.2.header.layers = [2, 1] ∧
      entry.2.header.payload = start.frame.payload ∧
      entry.2.header.originDomain = start.frame.originDomain :=
  Requirements.every_distributed_black_piece_is_double_protected config expectedEncapStack redSources blackIfaces
    encodedBytes local_stack_conditions sources_checked black_ifaces_checked origin run

end TDN.Deployments.DualStack_RedV4_GrayV6_BlackV6

namespace TDN.Deployments.DualStack_RedV6_GrayV4_BlackV4

theorem each_fragment_at_black_retains_protection {Byte : Type}
    (encodedBytes : DataPlaneForwarding.Frame → List Byte)
    {start : DataPlaneForwarding.State}
    {located : List (DataPlaneForwarding.State × Fragmentation.Fragment DataPlaneForwarding.FragmentDescriptor Byte)}
    {actions : List (Option DataPlaneForwarding.Action)}
    (origin : Requirements.RedPayloadOrigin config redSources start)
    (run : (Fragmentation.distributed (DataPlaneForwarding.lts config)
      (DataPlaneForwarding.encodeForFragmentation encodedBytes)).MTr (.whole start) actions (.pieces located)) :
    ∀ entry ∈ located, entry.1.datapathStage = .egressReady → entry.1.iface ∈ blackIfaces →
      entry.2.header.layers = [2, 1] ∧
      entry.2.header.payload = start.frame.payload ∧
      entry.2.header.originDomain = start.frame.originDomain :=
  Requirements.every_distributed_black_piece_is_double_protected config expectedEncapStack redSources blackIfaces
    encodedBytes local_stack_conditions sources_checked black_ifaces_checked origin run

end TDN.Deployments.DualStack_RedV6_GrayV4_BlackV4

namespace TDN.Deployments.DualStack_RedV6_GrayV4_BlackV6

theorem each_fragment_at_black_retains_protection {Byte : Type}
    (encodedBytes : DataPlaneForwarding.Frame → List Byte)
    {start : DataPlaneForwarding.State}
    {located : List (DataPlaneForwarding.State × Fragmentation.Fragment DataPlaneForwarding.FragmentDescriptor Byte)}
    {actions : List (Option DataPlaneForwarding.Action)}
    (origin : Requirements.RedPayloadOrigin config redSources start)
    (run : (Fragmentation.distributed (DataPlaneForwarding.lts config)
      (DataPlaneForwarding.encodeForFragmentation encodedBytes)).MTr (.whole start) actions (.pieces located)) :
    ∀ entry ∈ located, entry.1.datapathStage = .egressReady → entry.1.iface ∈ blackIfaces →
      entry.2.header.layers = [2, 1] ∧
      entry.2.header.payload = start.frame.payload ∧
      entry.2.header.originDomain = start.frame.originDomain :=
  Requirements.every_distributed_black_piece_is_double_protected config expectedEncapStack redSources blackIfaces
    encodedBytes local_stack_conditions sources_checked black_ifaces_checked origin run

end TDN.Deployments.DualStack_RedV6_GrayV4_BlackV6

namespace TDN.Deployments.DualStack_RedV6_GrayV6_BlackV4

theorem each_fragment_at_black_retains_protection {Byte : Type}
    (encodedBytes : DataPlaneForwarding.Frame → List Byte)
    {start : DataPlaneForwarding.State}
    {located : List (DataPlaneForwarding.State × Fragmentation.Fragment DataPlaneForwarding.FragmentDescriptor Byte)}
    {actions : List (Option DataPlaneForwarding.Action)}
    (origin : Requirements.RedPayloadOrigin config redSources start)
    (run : (Fragmentation.distributed (DataPlaneForwarding.lts config)
      (DataPlaneForwarding.encodeForFragmentation encodedBytes)).MTr (.whole start) actions (.pieces located)) :
    ∀ entry ∈ located, entry.1.datapathStage = .egressReady → entry.1.iface ∈ blackIfaces →
      entry.2.header.layers = [2, 1] ∧
      entry.2.header.payload = start.frame.payload ∧
      entry.2.header.originDomain = start.frame.originDomain :=
  Requirements.every_distributed_black_piece_is_double_protected config expectedEncapStack redSources blackIfaces
    encodedBytes local_stack_conditions sources_checked black_ifaces_checked origin run

end TDN.Deployments.DualStack_RedV6_GrayV6_BlackV4

namespace TDN.Deployments.DualStack_RedV6_GrayV6_BlackV6

theorem each_fragment_at_black_retains_protection {Byte : Type}
    (encodedBytes : DataPlaneForwarding.Frame → List Byte)
    {start : DataPlaneForwarding.State}
    {located : List (DataPlaneForwarding.State × Fragmentation.Fragment DataPlaneForwarding.FragmentDescriptor Byte)}
    {actions : List (Option DataPlaneForwarding.Action)}
    (origin : Requirements.RedPayloadOrigin config redSources start)
    (run : (Fragmentation.distributed (DataPlaneForwarding.lts config)
      (DataPlaneForwarding.encodeForFragmentation encodedBytes)).MTr (.whole start) actions (.pieces located)) :
    ∀ entry ∈ located, entry.1.datapathStage = .egressReady → entry.1.iface ∈ blackIfaces →
      entry.2.header.layers = [2, 1] ∧
      entry.2.header.payload = start.frame.payload ∧
      entry.2.header.originDomain = start.frame.originDomain :=
  Requirements.every_distributed_black_piece_is_double_protected config expectedEncapStack redSources blackIfaces
    encodedBytes local_stack_conditions sources_checked black_ifaces_checked origin run

end TDN.Deployments.DualStack_RedV6_GrayV6_BlackV6
