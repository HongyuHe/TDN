import TDN.Evidence.FreshComponentByteResponses
import TDN.Evidence.FreshSharedIsolationWitness

open TDN Execution
open TDN.Imported.FreshSharedIsolation
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def responses := UniformDomainResponses.responseConfig config
  TDN.Imported.FreshSharedExecution.responseGateways uniformResponseOwners

def replyHeader : PacketPolicy.Packet :=
  { witnessState60.frame.packet with source := 167903498, destination := 167837962 }

lemma host_reply_route : responses.selectedRoute witnessState60 replyHeader 196 := by
  refine ⟨⟨196, 196, 0, 4294967295, 0, 0, 32766⟩, ?_, rfl, rfl⟩
  change SelectedRoute TDN.Imported.FreshSharedExecution.routes
    ⟨196, 196, 0, 4294967295, 0, 0, 32766⟩ replyHeader
  unfold SelectedRoute Route.matches
  decide

lemma host_reply_emit : (KernelResponses.lts (lts config) responses).Tr
    (.routed witnessState60 .echo replyHeader 196) .emit
    (.network (responses.emit witnessState60 replyHeader 196)) := by
  apply KernelResponses.Step.emit
  · decide
  · decide

-- A delivered packet may generate and emit an actual permitted host reply.
example : (KernelResponses.lts (lts config) responses).MTr
    (.network witnessState60) [.generate, .route, .emit]
    (.network (responses.emit witnessState60 replyHeader 196)) := by
  apply Cslib.LTS.MTr.stepL
    (KernelResponses.Step.generate witnessState60 .echo replyHeader
      (every_active_component_can_generate witnessState60 (by decide)) (Or.inl rfl))
  apply Cslib.LTS.MTr.stepL (KernelResponses.Step.route _ _ _ _ host_reply_route)
  exact Cslib.LTS.MTr.stepL host_reply_emit Cslib.LTS.MTr.refl

-- Both imported inventories include the transport, firewall, bridge and host
-- owners in the checked cases. No source-domain constraint is assumed here.
example (state : Execution.State) (active : state.datapathStage ≠ .dropped) :
    responses.generates state := every_active_component_can_generate state active

-- A Black-router error quote retains already encrypted byte provenance.
example : DomainInvariant config domainLayout1 domainAllowed1
    (responses.emit witnessState31
      { witnessState31.frame.packet with protocol := "icmp" } 5) := by
  change witnessState31.frame.tags = domainLayout1 5 ∧ domainAllowed1 5
  unfold domainAllowed1
  decide
