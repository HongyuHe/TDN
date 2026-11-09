"""Apply shared byte-protection proofs and retain all accepted useful mixed paths."""
from pathlib import Path
import re

ROOT = Path(".")
OUTPUT = ROOT / "TDN/Deployments/SnapshotMixedByteProtection.lean"

def main():
    checks = [ROOT / "TDN/Deployments/TunnelMatrix_EncapStackChecks.lean",
              ROOT / "TDN/Deployments/SnapshotBridgedMacsecChecks.lean"]
    namespaces = [name for path in checks for name in
                  re.findall(r"^namespace (TDN\.Deployments\.\w+)$", path.read_text(), re.M)]
    assert len(namespaces) == 7
    text = ["import TDN.Requirements.HybridIpsecMacsecByteProtection",
            "import TDN.Deployments.TunnelMatrix_EncapStackChecks",
            "import TDN.Deployments.SnapshotBridgedMacsecChecks",
            "import TDN.Deployments.SnapshotMixedDeliverySuite", ""]
    for namespace in namespaces:
        text.append(f"""namespace {namespace}
open MultiProtocolForwarding

theorem every_mixed_byte_keeps_stack {{Byte : Type}}
    {{after : List (ByteFlows.Carrier MultiProtocolForwarding.State Byte)}}
    {{actions : List (ByteFlows.Action MultiProtocolForwarding.Action)}}
    (run : (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr [] actions after) :
    ByteFlows.Safe (fun _ => EncapStackConsistent config expectedEncapStack) after :=
  Requirements.mixed_bytes_keep_protection config expectedEncapStack redSources mixed_local_conditions
    red_sources_checked run

theorem every_mixed_black_byte_has_actual_layer_order {{Byte : Type}}
    {{after : List (ByteFlows.Carrier MultiProtocolForwarding.State Byte)}}
    {{actions : List (ByteFlows.Action MultiProtocolForwarding.Action)}}
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

end {namespace}
""")
    suite = (ROOT / "TDN/Deployments/SnapshotMixedDeliverySuite.lean").read_text()
    modules = re.findall(r"^import (TDN\.Evidence\.\w+)$", suite, re.M)
    assert len(modules) == 18
    for module in modules:
        source = (ROOT / (module.replace(".", "/") + ".lean")).read_text()
        namespace = re.search(r"^namespace (\S+)", source, re.M)[1]
        final = re.search(r"theorem positive_mixed_delivery .* usefulActions (usefulState\d+) :=", source)[1]
        text.append(f"""namespace {namespace}
open MultiProtocolForwarding

theorem positive_three_byte_delivery :
    (byteSystem config (Requirements.MixedByteOrigin redSources)).MTr []
      (ByteFlows.Action.inject :: usefulActions.map ByteFlows.Action.network)
      [⟨{final}, ([1, 2, 3] : List Nat)⟩] := by
  have injection :
      ByteFlows.Step (lts config) (Requirements.MixedByteOrigin redSources) PlainByteAssembly
        [] .inject [⟨usefulState0, ([1, 2, 3] : List Nat)⟩] :=
    .inject (fun _ _ => useful_red_origin)
  exact .stepL injection (ByteFlows.network_trace_on_one_carrier (lts config)
    (Requirements.MixedByteOrigin redSources) PlainByteAssembly [1, 2, 3] positive_mixed_delivery)

end {namespace}
""")
    OUTPUT.write_text("\n".join(text))
    print({"configurations": len(namespaces), "positive_byte_paths": len(modules), "output": str(OUTPUT)})

if __name__ == "__main__":
    main()
