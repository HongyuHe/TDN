"""Generate finite source/output reply checks from a validated family report."""
import argparse
import json
from pathlib import Path

from import_family_execution import render_rules
from import_snapshot import lean_list
from validate_evidence import require


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report")
    parser.add_argument("--module", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--trace")
    parser.add_argument("--witness-module")
    args = parser.parse_args()
    report = json.loads(Path(args.report).read_text())
    guards = report["early_source_guards"]
    require(guards, "No raw-bound early source guards")
    values = []
    for device, guard in sorted(guards.items()):
        require(guard["priority"] == -460 and guard["fallback"] == "allow", "Wrong guard semantics")
        values.append("⟨" + str(report["device_ids"][device]) + ", " + render_rules(guard["rules"]) + "⟩")
    text = """import TDN.Semantics.SourceResponseGuards
import """ + args.module + """

namespace TDN.Imported.""" + args.namespace + """

def responseSourceGuards : List (Nat × List PacketPolicy.Rule) := """ + lean_list(values) + """

set_option maxRecDepth 10000
set_option maxHeartbeats 2000000

lemma all_input_interfaces_covered :
    SourceResponseGuards.FiniteGuardCoverage ifaces responseSourceGuards := by decide

lemma all_source_output_reply_pairs_checked :
    SourceResponseGuards.FiniteReplyChecks devices ifaces responseSourceGuards := by decide

/-- Local guard checks cover every gateway input/output pair and every installed
inbound authentication alternative. The general theorem still requires actual
ingress acceptance, rule coverage and the kernel's return-to-source relation. -/
theorem source_output_reply_layers
    {guard : Nat × List PacketPolicy.Rule} (guardMember : guard ∈ responseSourceGuards)
    {entry output : Execution.IfaceData} (entryMember : entry ∈ ifaces)
    (entryOwner : entry.owner = guard.1) (inputExternal : entry.name ≠ "lo")
    (outputMember : output ∈ ifaces) (owner : output.owner = entry.owner)
    (outputExternal : output.name ≠ "lo") {auth : List Nat}
    (authenticated : auth ∈ Execution.possibleAuthentications
      (Execution.deviceAt devices entry.owner) entry)
    (original reply : PacketPolicy.Packet)
    (inputName : original.ingress = entry.name) (outputName : reply.egress = output.name)
    (inputAuth : original.inboundPolicies = auth)
    (selectorBound : ∀ id ∈ auth, ∃ association ∈ (Execution.deviceAt devices entry.owner).inbound,
      association.id = id ∧ association.matches original = true)
    (address : SourceResponseGuards.ValidSourceAddress original.source)
    (inputAccepted : Filter.evaluate (guard.2.map PacketPolicy.Rule.toFilter) .allow original = .allow)
    (outputAccepted : Filter.evaluate
      ((Execution.deviceAt devices output.owner).outputRules.map PacketPolicy.Rule.toFilter) .deny reply = .allow)
    (returnsToSource : reply.destination = original.source)
    (protocol : KernelResponses.ResponseProtocol reply.protocol) :
    (if auth = [] then entry.stack else entry.stack.tail) = output.stack :=
  SourceResponseGuards.finite_reply_checks_preserve_layers
    devices ifaces responseSourceGuards all_source_output_reply_pairs_checked
    guardMember entryMember entryOwner inputExternal outputMember owner outputExternal authenticated
    original reply inputName outputName inputAuth selectorBound
    (SourceResponseGuards.finite_guard_coverage_excludes_fallback ifaces responseSourceGuards
      all_input_interfaces_covered guardMember entryMember entryOwner inputExternal original inputName address)
    inputAccepted outputAccepted returnsToSource protocol

end TDN.Imported.""" + args.namespace + "\n"
    if args.trace:
        require(args.witness_module, "Trace checks require the imported witness module")
        trace = json.loads(Path(args.trace).read_text())
        interfaces = {row["id"]: row for row in report["model_snapshot"]["interfaces"]}
        by_port = {number: interfaces[name] for name, number in report["port_ids"].items()}
        guard_index = {name: index for index, name in enumerate(sorted(guards))}
        checks = []
        for index, state in enumerate(trace["states"]):
            interface = by_port[state["port"]]
            device = interface["device_id"]
            if state["phase"] not in {"received", "ingress"} or device not in guard_index:
                continue
            state_name = "witnessState" + str(index)
            rules = "(responseSourceGuards[" + str(guard_index[device]) + "]'(by decide)).2"
            packet = "{ " + state_name + ".frame.packet with ingress := " + json.dumps(interface["name"]) + ", inboundPolicies := " + state_name + ".authenticated }"
            checks.append("lemma positive_source_guard_" + str(index) + " : Filter.evaluate (" +
                          rules + ".map PacketPolicy.Rule.toFilter) .allow (" + packet + ") = .allow := by decide")
        text = "import " + args.witness_module + "\n" + text
        text = text.replace("end TDN.Imported." + args.namespace,
                            "\n".join(checks) + "\n\nend TDN.Imported." + args.namespace)
    Path(args.output).write_text(text)


if __name__ == "__main__":
    main()
