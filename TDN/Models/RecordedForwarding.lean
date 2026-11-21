import TDN.Models.TableDrivenDataPlane

namespace TDN.DataPlaneForwarding.RecordedForwarding

deriving instance DecidableEq for EncapHeaderLayer, IpsecFrame, ForwardingState

private instance (routes : List FibRoute) (route : FibRoute) (p : PacketPolicy.Packet) :
    Decidable (SelectedFibRoute routes route p) := by unfold SelectedFibRoute FibRoute.matches; infer_instance

private instance (s : InstalledSa) (p : IpsecPolicy) : Decidable (saMatchesPolicy s p) := by
  unfold saMatchesPolicy
  infer_instance

private instance (rules : List PacketPolicy.PacketAclRule) (fallback : Filter.Verdict) (p : PacketPolicy.Packet) :
    Decidable (PacketPolicy.AclAllows rules fallback p) := by unfold PacketPolicy.AclAllows; infer_instance

abbrev Hop (c : DataPlaneModel) (s : ForwardingState) :=
  { pair : ForwardingAction × ForwardingState // ForwardingStep c s pair.1 pair.2 }

private def hop {c : DataPlaneModel} {s : ForwardingState} {a : ForwardingAction} {t : ForwardingState}
    (step : ForwardingStep c s a t) : Hop c s := ⟨(a, t), step⟩

def candidates (c : DataPlaneModel) [∀ i j, Decidable (c.link i j)]
    [∀ i j p, Decidable (c.bridging i j p)] [∀ i a, Decidable (c.localAddress i a)]
    (s target : ForwardingState) : List (Hop c s) := by
  obtain ⟨i, stage, f, auth⟩ := s
  let tracking := target.frame.packet.connectionState
  let next := target.iface
  let drop := hop (ForwardingStep.drop (c := c) ⟨i, stage, f, auth⟩)
  refine drop :: ?_
  cases stage with
  | received =>
    cases auth with
    | cons => exact []
    | nil =>
      refine hop (.receive tracking) :: ?_
      cases shape : f.encapLayers with
      | nil => exact []
      | cons layer rest =>
        exact (c.ingressPolicies i).attach.flatMap fun ⟨p, configured⟩ =>
          (c.ingressSAs i).attach.filterMap fun ⟨sa, installed⟩ =>
            if h : saMatchesPolicy sa p ∧ layer.authentication = p.seal sa ∧
                f.packet.source = p.sender ∧ f.packet.destination = p.receiver ∧
                f.packet.protocol = "esp" ∧ p.matches layer.header = true then
              some (hop (.decrypt p sa layer.header rest tracking configured installed h.1
                (by rw [shape]; rw [← h.2.1]) h.2.2.1 h.2.2.2.1 h.2.2.2.2.1 h.2.2.2.2.2))
            else none
  | ingress =>
    exact (c.routes.filterMap fun r =>
      if h : r.egress = next ∧ r.ingress = i ∧ SelectedFibRoute c.routes r f.packet then some (hop (.route r h.2.2 h.2.1)) else none) ++
      (if h : c.bridging i next f.packet then [hop (.bridge h)] else []) ++
      (if h : c.localAddress i f.packet.destination ∧ PacketPolicy.AclAllows (c.inputRules i) (c.inputFallback i)
          (policyPacket c i f auth) then [hop (.deliverToLocalHost h.1 h.2)] else [])
  | localOutput =>
    cases auth with
    | cons => exact []
    | nil => exact c.routes.filterMap fun r =>
        if h : r.egress = next ∧ r.ingress = i ∧ SelectedFibRoute c.routes r f.packet then some (hop (.routeLocalOutput r h.2.2 h.2.1)) else none
  | routed =>
    exact if h : PacketPolicy.AclAllows (c.forwardRules i) (c.forwardFallback i) (policyPacket c i f auth)
      then [hop (.filter h)] else []
  | outputRouted =>
    cases auth with
    | cons => exact []
    | nil => exact if h : PacketPolicy.AclAllows (c.outputRules i) (c.outputFallback i) (policyPacket c i f [])
        then [hop (.outputFilter h)] else []
  | filtered =>
    exact (if h : lookupSpdPolicies (c.egressPolicies i) f.packet = [] then [hop (.forwardWithoutEncap h)] else []) ++
      ((lookupSpdPolicies (c.egressPolicies i) f.packet).attach.flatMap fun ⟨p, selected⟩ =>
        (c.egressSAs i).attach.filterMap fun ⟨sa, installed⟩ =>
          if h : saMatchesPolicy sa p then some (hop (.encrypt p sa selected installed h)) else none)
  | encapsulated =>
    exact c.routes.filterMap fun r =>
      if h : r.egress = next ∧ r.ingress = i ∧ SelectedFibRoute c.routes r f.packet then some (hop (.routeOuterPacket r h.2.2 h.2.1)) else none
  | egressReady => exact if h : c.link i next then [hop (.linkTransmit h)] else []
  | localInput =>
    cases recipient : c.ifaceSecurityDomain i with
    | none => exact []
    | some domain => exact if h : f.encapLayers = [] then [hop (.deliver domain recipient h)] else []
  | delivered | dropped => exact []

variable (c : DataPlaneModel) [∀ i j, Decidable (c.link i j)]
  [∀ i j p, Decidable (c.bridging i j p)] [∀ i a, Decidable (c.localAddress i a)]

def admits (s : ForwardingState) (a : ForwardingAction) (t : ForwardingState) : Bool :=
  (candidates c s t).any fun h => decide (h.val = (a, t))

theorem step_of_admits {s t : ForwardingState} {a : ForwardingAction}
    (accepted : admits c s a t = true) : ForwardingStep c s a t := by
  obtain ⟨h, _, same⟩ := List.any_eq_true.mp accepted
  have eq := of_decide_eq_true same
  have step := h.property
  rw [eq] at step
  exact step

end TDN.DataPlaneForwarding.RecordedForwarding
