import TDN

namespace MSCFirewallControlRegression
open TDN.MSC TDN.MSC.Deployment TDN.MSC.FirewallControl

def outgoing : RoutedPacket :=
  { input := "", output := "outside", source := (ipv4? "172.21.11.1").getD 0,
    destination := 3758096389, protocol := 89 }

example : localDecision .output "OF_A1" outgoing = some true := by decide
example : localDecision .input "OF_A1"
    { outgoing with input := "outside", output := "", source := (ipv4? "172.21.11.2").getD 0 } = some true := by decide
example : localDecision .output "OF_A1" { outgoing with protocol := 17 } = some false := by decide
example : localDecision .output "OF_A1" { outgoing with source := 3221226107 } = some false := by decide
example : localDecision .output "OF_A1" { outgoing with destination := 2887068674 } = some false := by decide
example : localDecision .output "OF_A1" { outgoing with output := "inside" } = some false := by decide

example : localDecision .input "GF_A" outgoing = some false := by decide

example (device : Device) (member : device ∈ devices) (gray : device.role = .grayFirewall)
    (packet : RoutedPacket) (external : packet.input ≠ "lo") :
    localDecision .input device.id packet = some false :=
  gray_firewall_rejects_external_local_traffic device member gray .input packet external

example : ∀ adjacency ∈ adjacencies,
    ∀ direction ∈ [LocalDirection.input, .output], ∀ grant ∈ adjacency.grants direction,
      localDecision direction adjacency.owner (grantPacket direction grant) = some true :=
  every_adjacency_permits_declared_controls

end MSCFirewallControlRegression
