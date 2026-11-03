"""Project snapshot facts into Lean-compatible JSON; never emit Lean source."""
from .parsers.packet_policy import parse_rule
from .adapters import Unsupported


def atom_json(atom):
    kind = atom["kind"]
    if kind in {"sourceRange", "destinationRange", "networkBytesRange"}:
        fields = {"low": atom["low"], "high": atom["high"]}
    elif kind in {"ingress", "egress", "protocol"}:
        fields = {"name": atom["value"]}
    elif kind in {"sourcePorts", "destinationPorts"}:
        fields = {"ports": atom["values"]}
    elif kind == "connectionStates":
        fields = {"states": atom["values"]}
    elif kind in {"inboundPolicy", "outboundPolicy"}:
        fields = {"requestId": atom["value"]}
    elif kind in ["ipsecUDPFraming", "ipsecUDPFramingWithOptions"]:
        return kind
    elif kind == "ipv4HeaderWords":
        fields = {"words": atom["value"]}
    elif kind in {"icmpType", "icmpCode", "hopLimit"}:
        fields = {"value": atom["value"]}
    else:
        raise Unsupported("Unknown normalized filter atom")
    return {kind: fields}


def packet_filters(snapshot):
    values = {}
    coverage = []
    for chain in snapshot["filters"]:
        try:
            rules = [parse_rule(r) for r in chain["ordered_rules"]]
            values[chain["id"]] = [{"atoms": [atom_json(a) for a in r["atoms"]], "verdict": r["verdict"]} for r in rules]
            coverage.append({"id": chain["id"], "status": "parsed", "policy": chain["policy"], "observationIds": chain["observation_ids"]})
        except Unsupported as error:
            coverage.append({"id": chain["id"], "status": "unsupported", "reason": str(error)})
    return values, coverage


PROJECTIONS = {}


def register_projection(name, version, project):
    """Register a trusted local projection from validated saved observations to JSON."""
    if name in {"inventory", "topology", "packet_filters", "multi_protocol_execution"} or name in PROJECTIONS:
        raise ValueError("Projection already registered: " + name)
    PROJECTIONS[name] = (version, project)
