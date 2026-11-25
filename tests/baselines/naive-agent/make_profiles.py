"""Freeze reproducible mutations and their document requirements before detection."""

import argparse
from pathlib import Path
import json

from common import BASE, now, sha256, write_json


REQUIREMENTS = {
    "MSC-VG-1": {"page": 38, "text": "The proposals offered by VPN Gateways in the course of establishing the Internet Key Exchange (IKE) Security Association and the Encapsulating Security Payload (ESP) SA for inner and outer tunnels must be configured to offer algorithm suite(s) containing only CNSA 1.0 algorithms as detailed in Table 6.", "interpretation": "The experiment selects the CNSA 1.0 branch. AES-128 is outside every listed alternative."},
    "MSC-VG-4": {"page": 38, "text": "When using certificate-based authentication, a unique device certificate must be loaded onto each VPN Gateway along with the corresponding CA certificate chain, to include the Trust Anchor CA certificate."},
    "MSC-VG-6": {"page": 38, "text": "A device certificate must be used for VPN Gateway authentication during IKE."},
    "MSC-VG-7": {"page": 38, "text": "VPN Gateway authentication must include a check that the certificate is not revoked, which can include a CRL, OCSP Responder, or other similar revocation reporting mechanism."},
    "MSC-VG-9": {"page": 38, "text": "All VPN Gateways must use IKEv2 (IETF RFC 7296) key exchange."},
    "MSC-VG-13": {"page": 39, "text": "All VPN Gateways must set the IKE SA lifetime to at most 24 hours."},
    "MSC-VG-14": {"page": 39, "text": "All VPN Gateways must set the ESP SA lifetime to no more than 8 hours."},
    "MSC-IR-1": {"page": 42, "text": "The Inner VPN Gateway must use ESP Tunnel mode IPsec, with an associated IP tunneling protocol."},
    "MSC-OR-1": {"page": 43, "text": "Outer VPN Gateways must use ESP Tunnel mode IPsec."},
    "MSC-IR-3": {"page": 43, "text": "The Inner Encryption Component must not allow packets received on an interface connected to a Red Network to bypass encryption and be forwarded out through an interface connected to a Gray Network."},
    "MSC-IR-5": {"page": 43, "text": "The Inner Encryption Component must not allow packets received on an interface connected to a Gray Network to bypass decryption and be forwarded out through an interface connected to a Red Network."},
    "MSC-OR-2": {"page": 43, "text": "Outer Encryption Components must not allow packets received on an interface connected to a Gray Network to bypass encryption and be forwarded out through an interface connected to a Black Network."},
    "MSC-OR-5": {"page": 44, "text": "Outer Encryption Components must not allow any packets received on an interface connected to a Black Network to bypass decryption.", "interpretation": "The test uses forwarded application data, outside the CP's permitted control traffic."},
    "MSC-OR-8": {"page": 44, "text": "Outer Encryption Components must not use routing protocols (e.g., OSPF, BGP)."},
    "MSC-PF-2": {"page": 44, "text": "All Solution Components must have all unused network interfaces disabled.", "interpretation": "A declared spare, unconnected virtual interface is the emulated counterpart of an unused interface."},
    "MSC-PF-9": {"page": 45, "text": "Multicast messages received on external interfaces of Outer Encryption Components must be dropped."},
    "MSC-PF-11": {"page": 45, "text": "For solutions using IPv4, each VPN Gateway must only accept packets with Transmission Control Protocol (TCP), User Datagram Protocol (UDP), ESP, or ICMP in the IPv4 Protocol field and drop all other packets."},
    "MSC-PF-17": {"page": 46, "text": "The Gray Network interfaces of Outer Encryption Components must only permit packets whose source and destination IP addresses match the external interfaces of Inner Encryption Components that support Red Networks of the same security level.", "interpretation": "The test targets an unlisted destination. It does not rely on the document's disputed same-level firewall sentence."},
    "MSC-PF-18": {"page": 46, "text": "The Gray Network interfaces of Outer Encryption Components must block all packets whose source address does not match a list of addresses or address ranges known to be reachable from the interface where the packet was received."},
    "MSC-PF-22": {"page": 46, "text": "If an Outer Firewall is required, for all Outer Firewall interfaces, traffic filtering rules must be applied to both inbound and outbound traffic, such that only IKE, ESP, MKA, MACsec and control plane protocols (as defined in this CP) approved by organization-defined policy are allowed.", "interpretation": "Each test declares Black to represent public Internet transport. The extra HTTP service is not an approved control service."},
}


def address(device, iface):
    return next(i["address"].split("/")[0] for i in device["interfaces"] if i["name"] == iface)


def make_profile(deployment, number):
    spec = deployment["spec"]
    devices = {d["id"]: d for d in spec["devices"]}
    prefix = spec["devices"][0]["id"].split("_")[0]
    site = "A" if number % 2 else "B"
    remote = "B" if site == "A" else "A"
    level, other_level = (3, 4) if number in {3, 4} else (1, 2)
    names = {
        "inner": f"{prefix}_I_{site}{level}", "peer": f"{prefix}_I_{remote}{level}",
        "other": f"{prefix}_I_{site}{other_level}", "other_peer": f"{prefix}_I_{remote}{other_level}",
        "outer": f"{prefix}_O_{site}1", "outer_peer": f"{prefix}_O_{remote}1",
        "gray_firewall": f"{prefix}_GF_{site}", "outer_firewall": f"{prefix}_OF_{site}1",
        "red_host": f"{prefix}_R_{site}{level}",
    }
    for name in names.values():
        assert name in devices, name
    inside = "gray" if level == 1 else f"gray{level}"
    inner_address = address(devices[names["inner"]], "gray")
    peer_address = address(devices[names["peer"]], "gray")
    red_address = address(devices[names["red_host"]], "red")
    gray_gateway = address(devices[names["gray_firewall"]], f"s{level}")
    black_neighbor = address(devices[names["outer_firewall"]], "inside")
    outer_address = address(devices[names["outer"]], "black")
    port = 43000 + 100 * number
    cases = []

    def add(requirement, device, operation, description, **parameters):
        cases.append({"case_id": f"{deployment['id']}-{requirement}", "requirement": requirement,
                      "device": names[device], "operation": operation, "description": description,
                      "parameters": parameters, "validated": False})

    add("MSC-VG-1", "inner", "weak_proposal", "Append an AES-128 fallback after the approved proposal.")
    add("MSC-VG-4", "other_peer", "duplicate_certificate", "Replace one gateway's signing identity with its peer's certificate and key.", donor=names["other"])
    add("MSC-VG-6", "inner", "psk_authentication", "Use a pre-shared secret for the selected Inner pair.", peer=names["peer"])
    add("MSC-VG-7", "outer", "optional_revocation", "Permit authentication without revocation information and remove the loaded local CRLs.")
    add("MSC-VG-9", "other", "ikev1", "Select IKEv1 on a separate Inner pair.", peer=names["other_peer"])
    add("MSC-VG-13", "peer", "ike_lifetime", "Set the configured IKE lifetime above 24 hours.", hours=24 + number)
    add("MSC-VG-14", "other_peer", "esp_lifetime", "Set the configured ESP hard lifetime above eight hours.", hours=8 + number)
    add("MSC-IR-1", "other", "transport_mode", "Select ESP transport mode on an Inner gateway.")
    add("MSC-OR-1", "outer_peer", "transport_mode", "Select ESP transport mode on an Outer gateway.")
    add("MSC-IR-3", "inner", "allow_packet", "Allow a narrow Red-to-Gray plaintext flow before the IPsec-only rules.", chain="FORWARD", ingress="red", egress="gray", source=red_address, destination=gray_gateway, protocol="udp", destination_port=port + 10)
    add("MSC-IR-5", "inner", "allow_packet", "Allow a narrow Gray-to-Red plaintext flow without an inbound IPsec policy.", chain="FORWARD", ingress="gray", egress="red", source=gray_gateway, destination=red_address, protocol="udp", destination_port=port + 11)
    add("MSC-OR-2", "outer", "allow_packet", "Allow one Gray-to-Black data flow without an outbound IPsec policy.", chain="FORWARD", ingress=inside, egress="black", source=inner_address, destination=black_neighbor, protocol="udp", destination_port=port + 12)
    add("MSC-OR-5", "outer", "allow_packet", "Forward one Black-to-Gray plaintext data flow.", chain="FORWARD", ingress="black", egress=inside, source=black_neighbor, destination=inner_address, protocol="udp", destination_port=port + 13)
    add("MSC-OR-8", "outer_peer", "ospf", "Run an OSPF process in the Outer gateway's network and process namespaces.")
    add("MSC-PF-2", "peer", "unused_interface", "Leave a spare unconnected interface enabled.", interface="aux2")
    add("MSC-PF-9", "outer", "allow_multicast", "Accept one multicast group on the Black interface.", chain="INPUT", ingress="black", destination=f"239.23.{number}.7", protocol="udp", destination_port=port + 16, local_address=outer_address)
    add("MSC-PF-11", "peer", "allow_packet", "Accept GRE on an Inner gateway's Gray interface.", chain="INPUT", ingress="gray", destination=peer_address, protocol="gre")
    add("MSC-PF-17", "outer", "allow_unlisted_peer", "Allow IKE-port traffic to an address absent from the Inner peer inventory.", chain="FORWARD", ingress=inside, egress="black", source=inner_address, destination=f"10.250.{number}.7", protocol="udp", destination_port=500, gateway=black_neighbor)
    add("MSC-PF-18", "outer", "allow_packet", "Accept a remote site's Inner source address from the local Gray interface.", chain="FORWARD", ingress=inside, egress="black", source=peer_address, destination=black_neighbor, protocol="udp", destination_port=port + 19)
    add("MSC-PF-22", "outer_firewall", "allow_http", "Accept an unapproved HTTP service on the Black-facing firewall interface.", chain="INPUT", ingress="outside", destination=address(devices[names["outer_firewall"]], "outside"), protocol="tcp", destination_port=port + 20)
    assert len(cases) == len({c["requirement"] for c in cases}) == 20
    return {"network": deployment["id"], "source_profile": deployment["profile"],
            "worker": "hy@clnode176.clemson.cloudlab.us", "deployment_directory": deployment["directory"],
            "black_transport_interpretation": "Public Internet represented by the isolated Black underlay",
            "topology": spec, "mutations": cases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_id")
    args = parser.parse_args()
    run = BASE / "runs" / args.run_id
    deployments = json.loads((run / "deployments.json").read_text())
    profiles = [make_profile(d, i) for i, d in enumerate(deployments, 1)]
    destination = BASE / "legacy" / "profiles"
    if destination.exists():
        raise ValueError("Mutation profiles already exist; record a revision explicitly before replacing them")
    for profile in profiles:
        write_json(destination / (profile["network"] + ".json"), profile)
    write_json(BASE / "legacy" / "requirements.json", REQUIREMENTS)
    paths = sorted(destination.glob("*.json")) + [BASE / "legacy" / "requirements.json"]
    write_json(run / "injection-freeze.json", {
        "frozen_at": now(), "cases": 100,
        "files": {str(p.relative_to(BASE)): sha256(p.read_bytes()) for p in paths},
        "note": "The targets are frozen. Validation may reject a failed injection; it cannot silently relabel it as successful.",
    })
    print("Frozen five profiles with 20 distinct target requirements each.")


if __name__ == "__main__":
    main()
