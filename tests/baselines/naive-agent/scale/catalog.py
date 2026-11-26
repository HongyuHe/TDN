"""The supervisor's paired, one-fault design. The detector never receives this file."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Case:
    key: str
    rule: str
    clause: str
    title: str
    observation: str


CASES = (
    Case(
        "inner-peer-loopback",
        "§4.2.1",
        "RG-007.02",
        "Inner gateway negotiates with itself",
        "Loaded peer differs from its intended remote; fresh negotiation loses the intended child on both ends.",
    ),
    Case(
        "inner-mode",
        "MSC-IR-1",
        "RG-029.01",
        "Inner gateway selects transport mode",
        "The active connection listing reports transport for the protected child.",
    ),
    Case(
        "outer-mode",
        "MSC-OR-1",
        "RG-030.01",
        "Outer gateway selects transport mode",
        "The active connection listing reports transport for the protected child.",
    ),
    Case(
        "firewall-inside-disconnected",
        "MSC-SR-12",
        "RG-034.02",
        "Inside Outer Firewall link disappears",
        "The previously connected inside interface is absent at the registered firewall.",
    ),
    Case(
        "firewall-outside-disconnected",
        "MSC-SR-12",
        "RG-034.02",
        "Outside Outer Firewall link disappears",
        "The previously connected outside interface is absent at the registered firewall.",
    ),
    Case(
        "firewall-local-empty-udp",
        "MSC-PF-22",
        "RG-035.04",
        "Outer Firewall admits an unapproved UDP message",
        "The gateway registers the test message after its input filter.",
    ),
    Case(
        "inner-empty-ipv4-header",
        "MSC-PF-11",
        "RG-038.03",
        "Inner gateway accepts a disallowed IPv4 protocol",
        "The identified input allow rule and the receiving kernel both record protocol 253.",
    ),
    Case(
        "outer-eligible-deny",
        "MSC-PF-13",
        "RG-039.02",
        "Outer gateway drops an authorized same-level flow",
        "A previously working same-level flow hits the target deny and fails while independent deliveries succeed.",
    ),
    Case(
        "shared-inner-gateway",
        "§4.2.2",
        "RG-008.01",
        "Two Red networks use one Inner gateway",
        "Test traffic from two Red networks increments separate installed child counters on the same gateway.",
    ),
    Case(
        "gray-cross-level-path",
        "MSC-SR-7",
        "RG-013.01",
        "Different-level Inners share a firewall-free Gray path",
        "Both ends of the new live link match and a cross-level Gray path excludes all Gray Firewalls.",
    ),
    Case(
        "gray-cross-level-forward",
        "MSC-PF-28",
        "RG-040.02",
        "Gray Firewall forwards protected traffic between levels",
        "The same ESP bytes from unlike-level Inners appear on the two firewall interfaces.",
    ),
    Case(
        "outer-firewall-alternate-path",
        "MSC-SR-12",
        "RG-034.01",
        "A second Outer-to-Black path avoids the firewall",
        "The new link endpoints match while both original firewall links remain present.",
    ),
    Case(
        "outer-black-multicast",
        "MSC-PF-9",
        "RG-038.01",
        "Outer gateway receives Black-side multicast",
        "A receiver on the Outer gateway obtains the identified user datagram after input filtering.",
    ),
    Case(
        "inner-gray-application",
        "MSC-PF-5",
        "RG-035.02",
        "An ordinary Gray application reaches the Inner gateway",
        "An unapproved application datagram is received locally at the Inner's Gray address.",
    ),
    Case(
        "gray-ordinary-http",
        "MSC-PF-25",
        "RG-040.03",
        "Gray Firewall forwards ordinary HTTP",
        "An ordinary test request to a non-revocation destination is recorded on both sides of the Gray Firewall.",
    ),
    Case(
        "outer-gray-wrong-ingress",
        "MSC-PF-18",
        "RG-039.05",
        "Outer accepts a source on the wrong Gray interface",
        "A delivered packet's ingress and source disagree with the independently registered reachable prefixes.",
    ),
    Case(
        "outer-unintended-peer",
        "MSC-OR-10",
        "RG-035.01",
        "Outer gateway completes a connection to an unintended peer",
        "The two endpoints record a completed exchange and the remote device is outside the registered intended peers.",
    ),
    Case(
        "inner-cross-level-auth",
        "MSC-VG-15",
        "RG-008.02",
        "Inner gateways protecting different levels establish a tunnel",
        "After the Site B administrator changes its Red enclave designation, a fresh authenticated session and installed child appear at both endpoints. The Red host and its administrative workstation independently record the level.",
    ),
    Case(
        "inner-gray-plaintext-delivery",
        "MSC-IR-5",
        "RG-029.03",
        "Plaintext crosses from Gray through an Inner to Red",
        "The same marked plaintext enters on Gray and leaves on Red without a decryption operation.",
    ),
    Case(
        "gray-authorized-ike-deny",
        "MSC-PF-23",
        "RG-040.01 / RG-040.07",
        "Gray Firewall denies IKE between authorized same-level peers",
        "An exact Gray Firewall deny counts the fresh IKE packets. The same designated peers establish a child before the change and after restoration.",
    ),
)
BY_NAME = {c.key: c for c in CASES}

CHANGES = {
    "inner-peer-loopback": "Load the Site A Inner gateway's own loopback address as its runtime remote peer. Its saved settings still name the peer at Site B. Ask for a new tunnel.",
    "inner-mode": "Change the runtime mode of the Site A Inner gateway's protected IPsec connection from tunnel to transport.",
    "outer-mode": "Change the runtime mode of the Site A Outer gateway's protected IPsec connection from tunnel to transport.",
    "firewall-inside-disconnected": "Temporarily detach the inside interface of Site A’s Outer Firewall. Check both ends of every registered link.",
    "firewall-outside-disconnected": "Temporarily detach the outside interface of Site A’s Outer Firewall. Its inside connection to the Outer gateway stays up.",
    "firewall-local-empty-udp": "Add one input exception on the Outer Firewall for the fixed UDP diagnostic. Send one application-free datagram from the adjacent Black test segment.",
    "inner-empty-ipv4-header": "Add a narrow input exception at the Inner gateway for an empty IPv4 packet with protocol number 253. Register the receiving kernel's decision.",
    "outer-eligible-deny": "On Site A's Outer gateway, deny the otherwise permitted traffic between the designated level-one Inner peers. Exercise all declared Red pairs.",
    "shared-inner-gateway": "Add a second Red attachment to one Inner gateway and a test tunnel child for that enclave. Check which running gateway processes traffic for the two distinct Red networks.",
    "gray-cross-level-path": "Add one address-free Gray link between different-level Inner gateways. The ordinary firewall-connected paths remain present. The extra link discards test traffic and is scored for its placement.",
    "gray-cross-level-forward": "Give the Site A Gray Firewall one exception for protected traffic between different-level Inner gateways. Compare the same synthetic ESP packet on the incoming and outgoing interfaces.",
    "outer-firewall-alternate-path": "Connect the Outer gateway directly to the Black test network with a second, address-free link. The original firewall path stays up. The extra link discards traffic so only the placement clause is exercised.",
    "outer-black-multicast": "Add one input exception for a private multicast group on the Outer gateway's Black interface. A joined UDP socket checks whether the fixed group message reaches the gateway.",
    "inner-gray-application": "Permit one ordinary application datagram on the Inner gateway's Gray interface. The test client sends the same message with the clean and changed filters.",
    "gray-ordinary-http": "Permit one HTTP service through the Gray Firewall, including its replies. The test client requests an ordinary page from an endpoint outside the approved revocation service.",
    "outer-gray-wrong-ingress": "Permit a datagram arriving on the first Gray interface whose source belongs to the Gray router's second interface. The router sends with its own real address. The receiving socket reports the actual arrival interface.",
    "outer-unintended-peer": "Permit the Outer gateway to open a test TCP service on an unregistered Black-side endpoint and receive replies. The private measurement route already exists in the clean configuration.",
    "inner-cross-level-auth": "Reclassify Site B's first Red enclave from S1 to S2 through its administrative workstation. Read back the designation on the Red host, then request fresh authentication between the original Inner peers.",
    "inner-gray-plaintext-delivery": "Permit one ordinary test datagram through the Inner gateway from Gray to Red. Capture its unique payload at Gray ingress and on the Red-facing link.",
    "gray-authorized-ike-deny": "Insert one deny rule at Site A's Gray Firewall for IKE between the intended level-one Inner gateways. Request a fresh tunnel and read the rule counter. Repeat after restoring the rule.",
}
