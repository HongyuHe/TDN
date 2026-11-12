import TDN.Models.FibRouteCertificates

open TDN TDN.Certificates TDN.DataPlaneForwarding

namespace RouteCertificateTests

def fallback : FibRoute := ⟨0, 1, 0, 255, 0, 0, 10⟩
def preferred : FibRoute := ⟨0, 2, 32, 63, 27, 5, 10⟩
def equalCost : FibRoute := ⟨0, 3, 32, 63, 27, 5, 10⟩
def routes : WitnessTree FibRoute := .branch (.leaf fallback) (.branch (.leaf preferred) (.leaf equalCost))

def valid : RouteCertificate :=
  { destination := 42
    winners := .node (some [true, false]) .empty .empty
    retained := .branch (.leaf preferred) (.leaf equalCost)
    coverage := .branch (.leaf []) (.branch (.leaf [false]) (.leaf [true]))
    origins := .branch (.leaf [true, false]) (.leaf [true, true]) }

example : valid.check routes = true := by native_decide
example : ({ valid with coverage := .empty }).check routes = false := by native_decide
example : ({ valid with origins := .empty }).check routes = false := by native_decide
example : ({ valid with winners := .empty }).check routes = false := by native_decide
example : ({ valid with winners := .node (some [false]) .empty .empty }).check routes = false := by native_decide
example : ({ valid with winners := .node (some [true, true, false]) .empty .empty }).check routes = false := by native_decide
example : ({ valid with retained := .leaf preferred }).check routes = false := by native_decide
example : ({ valid with retained := .branch (.leaf preferred) (.leaf fallback) }).check routes = false := by native_decide
example : ({ valid with destination := 64 }).check routes = false := by native_decide
example : ({ valid with origins := .branch (.leaf [true, true]) (.leaf [true, false]) }).check routes = false := by native_decide
example : valid.check (.branch (.leaf { fallback with tablePriority := 1 })
    (.branch (.leaf preferred) (.leaf equalCost))) = false := by native_decide
example : valid.check (.branch (.leaf fallback)
    (.branch (.leaf { preferred with metric := 4 }) (.leaf equalCost))) = false := by native_decide
example : valid.check (.branch (.leaf fallback)
    (.branch (.leaf preferred) (.leaf { equalCost with ingress := 1 }))) = false := by native_decide

example (packet : PacketPolicy.Packet) (destination : packet.destination = 42) :
    SelectedFibRoute routes.values equalCost packet := by
  apply (table_driven_route_certificate_sound routes valid (by native_decide) equalCost packet destination).mpr
  native_decide
example (packet : PacketPolicy.Packet) (destination : packet.destination = 42) :
    ¬ SelectedFibRoute routes.values fallback packet := by
  rw [table_driven_route_certificate_sound routes valid (by native_decide) fallback packet destination]
  native_decide
example (routes : WitnessTree FibRoute) (certificate : RouteCertificate)
    (checked : certificate.check routes = true) (packet : PacketPolicy.Packet)
    (destination : packet.destination = certificate.destination) :
    ∀ route, SelectedFibRoute routes.values route packet ↔ route ∈ certificate.retained.values :=
  fun route => table_driven_route_certificate_sound routes certificate checked route packet destination

end RouteCertificateTests
