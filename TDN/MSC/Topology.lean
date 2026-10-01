import TDN.MSC.Deployment

/-!
# Facts about the deployed graph

Finite configuration facts use `decide`: Lean evaluates a decision procedure
and its kernel checks the resulting proof. The path result is stronger than
enumerating short paths. Induction covers walks of every finite length,
including walks that revisit a device. The graph still describes the imported
cables only; completeness with respect to the live host is an external premise.
-/
namespace TDN.MSC
open Deployment

/-- A lookup returns `none` for unknown names, rather than inventing a device. -/
def device? (id : String) : Option Device := devices.find? (fun d => d.id == id)

def role? (id : String) : Option Role := (device? id).map Device.role

def grayLabel (id : String) : Option (Site × SecurityLevel) := do
  let d ← device? id
  let site ← d.site
  let level ← d.level
  pure (site, level)

/-- An undirected cable supplies two directed edges. Removing every Gray
Firewall leaves exactly the paths that could bypass a Gray Firewall. -/
def grayEdges : List (String × String) :=
  (links.filter (fun l => l.zone == .gray &&
    role? l.a != some .grayFirewall && role? l.b != some .grayFirewall)).flatMap
      (fun l => [(l.a, l.b), (l.b, l.a)])

/-- `Walk edges a b` is evidence that a finite walk exists from `a` to `b`.
`refl` permits a zero-length walk. `step` prepends one known edge to a walk.
The definition does not choose a routing protocol or claim packet delivery. -/
inductive Walk (edges : List (String × String)) : String → String → Prop where
  | refl (a : String) : Walk edges a a
  | step {a b c : String} : (a, b) ∈ edges → Walk edges b c → Walk edges a c

/-- Any label preserved on each edge is preserved along an arbitrary walk.
The induction hypothesis describes the remaining walk after its first edge. -/
theorem walk_preserves {α : Type} (label : String → α)
    (edges : List (String × String))
    (localInvariant : ∀ e ∈ edges, label e.1 = label e.2)
    {a b : String} (path : Walk edges a b) : label a = label b := by
  induction path with
  | refl => rfl
  | step edge _ remaining => exact (localInvariant _ edge).trans remaining

/-- Only devices with retained data interfaces belong to the MSC proof scope.
Administration workstations and management-only switches are optional. The
importer removes their records and management ports before required validation.
The predicate also documents the scope inside Lean. -/
def retainedDevice (d : Device) : Bool :=
  d.role != .admin && d.interfaces.any (fun i => i.zone != .management)

def retainedDevices : List Device := devices.filter retainedDevice

def retainedLinks : List Link := links.filter (fun l => l.zone != .management)

theorem retained_device_count : retainedDevices.length = 23 := by decide

theorem retained_link_count : retainedLinks.length = 24 := by decide

/-- Sampled availability concerns only retained MSC devices. An unavailable
optional management workstation cannot falsify this observation theorem. -/
theorem sampled_retained_devices_running : ∀ o ∈ observations,
    (device? o.device).any retainedDevice = true →
    o.running = true ∧ o.errors = [] ∧ o.deployedSpecHash = specHash := by decide

theorem device_ids_unique : (devices.map Device.id).Nodup := by decide

/-- Every imported endpoint exists and both interfaces have the cable's zone. -/
theorem cable_endpoints_valid : ∀ l ∈ links,
    (devices.any (fun d => d.id == l.a &&
      d.interfaces.any (fun i => i.name == l.aPort && i.zone == l.zone))) = true ∧
    (devices.any (fun d => d.id == l.b &&
      d.interfaces.any (fun i => i.name == l.bPort && i.zone == l.zone))) = true := by
  decide

/-- Switch ports may have no address. Every nonempty Gray interface address is
retained, including both interfaces of each Gray Firewall. The uniqueness
check therefore covers all declared addressed Gray interfaces across sites
and security levels, rather than only the tunnel endpoint subset. -/
def addressedGrayInterfaces : List Interface :=
  (devices.flatMap Device.interfaces).filter (fun i => i.zone == .gray && !i.address.isEmpty)

/-- Parsing validity is checked separately so filterMap cannot conceal a
malformed address before the numeric uniqueness check. Prefix lengths do not
distinguish two assignments of the same IPv4 host address. -/
theorem gray_addresses_valid : ∀ i ∈ addressedGrayInterfaces,
    (Prefix.parse? i.address).isSome = true := by decide

theorem gray_addresses_unique :
    (addressedGrayInterfaces.filterMap (fun i =>
      (Prefix.parse? i.address).map Prefix.address)).Nodup := by decide

/-- Every Red-host cable reaches the inner role. Dedicated ownership is checked
separately below; a role restriction alone cannot identify a host's own inner. -/
theorem red_hosts_attach_to_inner : ∀ l ∈ links,
    (role? l.a = some .host → role? l.b = some .inner ∧ l.zone = .red) ∧
    (role? l.b = some .host → role? l.a = some .inner ∧ l.zone = .red) := by
  decide

/-- All Red cable neighbors, independent of cable orientation and ordering.
The preceding role theorem ensures that a host's neighbors are inner devices. -/
def redNeighbors (id : String) : List String :=
  (links.filter (fun l => l.zone == .red)).flatMap (fun l =>
    (if l.a == id then [l.b] else []) ++ (if l.b == id then [l.a] else []))

/-- Each representative Red host has one exclusive inner in its own site and
security level. Nonempty neighbor lists prevent disconnected hosts or inners
from satisfying the uniqueness clauses vacuously. Every host neighbor is that
inner, and every Red neighbor of the inner is that host. The statement concerns
declared logical devices, not physically independent certified products. -/
theorem red_hosts_have_dedicated_inner : ∀ host ∈ devices, host.role = .host →
    ∃ inner ∈ devices, inner.role = .inner ∧
      inner.site = host.site ∧ inner.level = host.level ∧
      redNeighbors host.id ≠ [] ∧ redNeighbors inner.id ≠ [] ∧
      (∀ neighbor ∈ redNeighbors host.id, neighbor = inner.id) ∧
      (∀ neighbor ∈ redNeighbors inner.id, neighbor = host.id) := by decide

/-- Every declared inner belongs to the checked Red-host mapping. The reverse
coverage check rules out silently omitting an unattached inner from the model. -/
theorem inner_devices_have_red_owner : ∀ inner ∈ devices, inner.role = .inner →
    ∃ host ∈ devices, host.role = .host ∧ inner.id ∈ redNeighbors host.id := by decide

/-- The local invariant is checked against every edge of the concrete snapshot.
An added cross-level bypass edge makes this proof fail on regeneration. -/
theorem gray_edges_preserve_label : ∀ e ∈ grayEdges,
    grayLabel e.1 = grayLabel e.2 := by decide

/-- Distinct labels cannot be connected after Gray Firewalls are removed.
Equivalently, every Gray walk connecting those labels in the full graph must
visit a removed firewall. The conclusion concerns physical cable paths, not
whether the firewall currently drops a packet. -/
theorem no_cross_level_gray_bypass (a b : String)
    (different : grayLabel a ≠ grayLabel b) : ¬ Walk grayEdges a b := by
  intro path
  exact different (walk_preserves grayLabel grayEdges gray_edges_preserve_label path)

theorem site_a_gray_cut : ¬ Walk grayEdges "I_A1" "I_A2" :=
  no_cross_level_gray_bypass _ _ (by decide)

theorem site_b_gray_cut : ¬ Walk grayEdges "I_B1" "I_B2" :=
  no_cross_level_gray_bypass _ _ (by decide)

/-- The retained data graph includes Red, Gray, and Black cables. Removing
Outer Firewall vertices tests whether any retained cable path bypasses them.
Management cables remain outside the experiment's data-path scope. -/
def dataEdges : List (String × String) :=
  (links.filter (fun l => l.zone != .management)).flatMap
    (fun l => [(l.a, l.b), (l.b, l.a)])

def withoutOuterFirewalls : List (String × String) :=
  dataEdges.filter (fun e => role? e.1 != some .firewall && role? e.2 != some .firewall)

def blackRegion (id : String) : Bool := id == "BLACK"

theorem outer_firewall_cut_edges : ∀ e ∈ withoutOuterFirewalls,
    blackRegion e.1 = blackRegion e.2 := by decide

theorem outer_devices_outside_black_region : ∀ d ∈ devices,
    d.role = .outer → blackRegion d.id = false := by decide

/-- Induction covers every finite cable walk, including detours through Gray.
The result supports N-12's untrusted-Black placement condition. SR-12 additionally
requires a Public Internet setting, which the snapshot does not establish. -/
theorem no_outer_firewall_bypass (d : Device) (member : d ∈ devices)
    (outer : d.role = .outer) : ¬ Walk withoutOuterFirewalls d.id "BLACK" := by
  intro path
  have same := walk_preserves blackRegion withoutOuterFirewalls outer_firewall_cut_edges path
  rw [outer_devices_outside_black_region d member outer] at same
  cases same

/-- Positive cable witnesses distinguish mandatory firewall placement from a
disconnected graph. Every outer device has a two-edge path through a firewall. -/
theorem outer_firewall_paths_present : ∀ d ∈ devices, d.role = .outer →
    ∃ firewall ∈ devices, firewall.role = .firewall ∧
      (d.id, firewall.id) ∈ dataEdges ∧ (firewall.id, "BLACK") ∈ dataEdges := by decide

theorem outer_has_black_cable_path (d : Device) (member : d ∈ devices)
    (outer : d.role = .outer) : Walk dataEdges d.id "BLACK" := by
  obtain ⟨firewall, _, _, first, second⟩ := outer_firewall_paths_present d member outer
  exact .step first (.step second (.refl "BLACK"))

/-- Every tunnel has a reverse declaration with matching endpoints, selectors,
trust domain, and policy ID. Eight endpoint records represent four peer pairs. -/
theorem tunnel_peers_symmetric : ∀ t ∈ tunnels,
    tunnels.any (fun p => p.owner == t.peer && p.peer == t.owner &&
      p.localAddress == t.remoteAddress && p.remoteAddress == t.localAddress &&
      p.localSelector == t.remoteSelector && p.remoteSelector == t.localSelector &&
      p.trust == t.trust && p.reqid == t.reqid) = true := by decide

theorem inner_peers_same_level : ∀ t ∈ tunnels,
    role? t.owner = some .inner →
      ((device? t.owner).bind Device.level) = ((device? t.peer).bind Device.level) := by
  decide

theorem inner_trust_domains_separate : ∀ a ∈ tunnels, ∀ b ∈ tunnels,
    role? a.owner = some .inner → role? b.owner = some .inner →
    ((device? a.owner).bind Device.level) ≠ ((device? b.owner).bind Device.level) →
    a.trust ≠ b.trust := by decide

theorem sampled_tunnels_established : ∀ o ∈ observations,
    (role? o.device = some .inner ∨ role? o.device = some .outer) →
    o.tunnelEstablished = some true := by decide

end TDN.MSC
