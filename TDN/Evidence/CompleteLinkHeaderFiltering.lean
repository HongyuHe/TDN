import TDN.Targets.LinkHeaderFiltering
import TDN.Import.Command

namespace TDN.Imported.CompleteLinkHeaderFiltering
open Compliance Targets Targets.Complete

set_option maxRecDepth 4096

tdn_data programs : List LinkAdmission.Program from "../../data/evidence/proof010-link-header/CapturedProgramsAndFrames.json" ["programs"]
tdn_data mka : LinkAdmission.Frame from "../../data/evidence/proof010-link-header/CapturedProgramsAndFrames.json" ["mka"]
tdn_data dataFrame : LinkAdmission.Frame from "../../data/evidence/proof010-link-header/CapturedProgramsAndFrames.json" ["data"]
tdn_data groupData : LinkAdmission.Frame from "../../data/evidence/proof010-link-header/CapturedProgramsAndFrames.json" ["groupData"]
tdn_data wrongActor : LinkAdmission.Frame from "../../data/evidence/proof010-link-header/CapturedProgramsAndFrames.json" ["wrongActor"]
tdn_data wrongLength : LinkAdmission.Frame from "../../data/evidence/proof010-link-header/CapturedProgramsAndFrames.json" ["wrongLength"]
tdn_data taggedMKA : LinkAdmission.Frame from "../../data/evidence/proof010-link-header/CapturedProgramsAndFrames.json" ["taggedMKA"]
tdn_data taggedData : LinkAdmission.Frame from "../../data/evidence/proof010-link-header/CapturedProgramsAndFrames.json" ["taggedData"]

def program (index : Nat) : LinkAdmission.Program := programs[index]?.getD ⟨[], .deny⟩

def level : SecurityLevel := ⟨"secret", ∅, ∅, ∅⟩

def component (owner : Nat) : String := if owner = 0 then "A" else "B"

def ifaceName (iface : Nat) : String :=
  if iface = 0 then "A/wire" else if iface = 1 then "B/wire"
  else if iface = 2 then "A/macsec" else "B/macsec"

def devices : List Device :=
  [⟨"A", "siteA", .macsec, some .outer, level, true⟩,
   ⟨"B", "siteB", .macsec, some .outer, level, true⟩]

def interfaces : List Interface :=
  [{ id := "A/wire", device := "A", zone := .black, address := none,
     linkAddress := some 2199026466817, physical := false, managementNetwork := false, mtu := some 1500 },
   { id := "B/wire", device := "B", zone := .black, address := none,
     linkAddress := some 2199026466818, physical := false, managementNetwork := false, mtu := some 1500 },
   { id := "A/macsec", device := "A", zone := .gray, address := none,
     physical := false, managementNetwork := false, mtu := some 1468 },
   { id := "B/macsec", device := "B", zone := .gray, address := none,
     physical := false, managementNetwork := false, mtu := some 1468 }]

def tunnels : List Tunnel :=
  [⟨"AB", .outer, .macsec, "A", "B", "capturedSAK", false, false⟩,
   ⟨"BA", .outer, .macsec, "B", "A", "capturedSAK", false, false⟩]

def peers : List PacketProcessing.MKAEndpoint :=
  [⟨0, 1, 144115398529318913, "AB"⟩, ⟨1, 0, 144115398529384449, "BA"⟩]

def macIface (physical logical : Nat) : MultiProtocolExecution.MACIface :=
  ⟨logical, physical, ⟨true, true, true, 0⟩, none, [], true⟩

def inventory (base : PacketProcessing.Inventory) : PacketProcessing.Inventory :=
  { base with
    ifaces := [0, 1, 2, 3], ifaceName := ifaceName, componentName := component,
    mkaPeers := peers, ipsecSizes := [],
    configuration := { base.configuration with
      ip := { base.configuration.ip with
        owner := fun iface => iface % 2, interfaceName := ifaceName,
        routes := [], outbound := fun _ => [], inbound := fun _ => [],
        localAddress := fun _ _ => False,
        forwardRules := fun _ => [], forwardFallback := fun _ => .deny },
      macIfaces := [macIface 0 2, macIface 1 3], carriers := [], bridge := fun _ _ => False,
      linkPolicies := [(0, ⟨program 0, program 1⟩), (1, ⟨program 2, program 3⟩)],
      networkBytes := fun body _ => body.visibleHeader.bind PacketPolicy.Packet.networkBytes } }

def deployment (base : Deployment) (processing : PacketProcessing.Inventory) : Deployment :=
  { base with
    devices := devices, interfaces := interfaces, tunnels := tunnels, policies := [],
    services := [], managementExchanges := [], managementHistory := [], udpBindings := [],
    grayWorkstation := fun _ => False, dropIPv4Options := fun _ => false,
    intendedPeer := fun source destination => (source, destination) ∈ [("A", "B"), ("B", "A")],
    policyApproved := fun _ traffic => traffic.trafficClass = .control,
    processing := some (inventory processing) }

instance (base : Deployment) (processing : PacketProcessing.Inventory) :
    DecidableRel (deployment base processing).intendedPeer := by
  intro source destination
  unfold deployment
  infer_instance

lemma link_header_records_checked (base : Deployment) (processing : PacketProcessing.Inventory) :
    LinkHeaderPolicyChecks (deployment base processing) (inventory processing) := by
  exact of_decide_eq_true rfl

theorem captured_link_program_model_RG038 (base : Deployment) (processing : PacketProcessing.Inventory) :
    msc_ip_header_and_multicast_filtering (deployment base processing) (fun _ => false) := by
  apply ip_and_link_header_filtering_from_inventory_and_rule_atoms
    (deployment base processing) (inventory processing) (fun _ => false)
  · intro _
    rfl
  · rfl
  · rfl
  · funext owner
    simp [deployment, grayWorkstationRole, Deployment.IsDevice, devices]
  · rfl
  · rfl
  · funext iface address
    simp [deployment, inventory, nativeLocalAddress, interfaces, Interface.HasLocalAddress]
  · rfl
  · rfl
  · unfold LinkPolicyRecordChecks Deployment.LinkPath
    dsimp [inventory, macIface]
    decide
  · exact link_header_records_checked base processing
  · intro interface member endpoint endpointMember name packet framing destination
    change ((deployment base processing).Observe packet).trafficClass = .control
    have records : MKAObservationRecords (deployment base processing) endpoint.actorSCI := by
      simp [MKAObservationRecords, deployment, devices]
    exact mka_observation_class _ packet endpoint.actorSCI records framing destination

lemma captured_positive_MKA_and_data :
    (program 1).Accepts (mka.Packet "" "A/wire") ∧
    (program 2).Accepts (mka.Packet "B/wire" "") ∧
    (program 1).Accepts (dataFrame.Packet "" "A/wire") ∧
    (program 2).Accepts (dataFrame.Packet "B/wire" "") := by decide

lemma captured_negative_group_actor_length_and_vlan :
    ∀ policy ∈ programs, ∀ frame ∈ [groupData, wrongActor, wrongLength, taggedMKA, taggedData],
      ¬ policy.Accepts (frame.Packet "wire" "wire") := by decide

end TDN.Imported.CompleteLinkHeaderFiltering

namespace TDN.Imported.CompleteLinkHeaderFiltering
open Compliance Targets Targets.Complete

lemma captured_bootstrap_MKA_is_fully_admitted
    (base : Deployment) (processing : PacketProcessing.Inventory) :
    (deployment base processing).Accepts "A/wire" .outbound
      ((deployment base processing).Observe (mka.Packet "" "A/wire")) ∧
    (deployment base processing).Accepts "B/wire" .inbound
      ((deployment base processing).Observe (mka.Packet "B/wire" "")) := by
  have framing : ∀ ingress egress,
      PacketMKA (mka.Packet ingress egress) := by
    intro ingress egress
    exact (show PacketMKA (mka.Packet "" "") from by decide)
  have supported : ∀ ingress egress,
      (deployment base processing).Supported
        ((deployment base processing).Observe (mka.Packet ingress egress)) := by
    intro ingress egress
    refine ⟨rfl, ?_⟩
    change (deployment base processing).ManagementMetadataBound (mka.Packet ingress egress)
    unfold Deployment.ManagementMetadataBound
    have control : PacketClass (mka.Packet ingress egress) = .control := by
      exact (show PacketClass (mka.Packet "" "") = .control from by decide)
    simp [control]
  constructor
  · refine ⟨.link, supported "" "A/wire", ?_, ?_⟩
    · refine ⟨inventory processing, rfl, 0, by simp [inventory], rfl,
        interfaces[0], by simp [deployment, interfaces], rfl, rfl, ?_⟩
      simp [PacketAtHook, HookDirection, inventory, ifaceName,
        LinkAdmission.Frame.Packet, Deployment.Observe]
    · refine ⟨⟨inventory processing, rfl, 0, by simp [inventory], rfl, Or.inr (Or.inl ?_)⟩,
        inventory processing, rfl, 0, by simp [inventory], rfl,
        ⟨program 0, program 1⟩, rfl, ?_⟩
      · refine ⟨framing "" "A/wire", ⟨0, 1, 144115398529318913, "AB"⟩,
          by simp [inventory, peers], rfl, mka.payload, rfl, ?_, ?_, ?_⟩
        all_goals exact of_decide_eq_true rfl
      · exact captured_positive_MKA_and_data.1
  · refine ⟨.link, supported "B/wire" "", ?_, ?_⟩
    · refine ⟨inventory processing, rfl, 1, by simp [inventory], rfl,
        interfaces[1], by simp [deployment, interfaces], rfl, rfl, ?_⟩
      simp [PacketAtHook, HookDirection, inventory, ifaceName,
        LinkAdmission.Frame.Packet, Deployment.Observe]
    · refine ⟨⟨inventory processing, rfl, 1, by simp [inventory], rfl, Or.inr (Or.inl ?_)⟩,
        inventory processing, rfl, 1, by simp [inventory], rfl,
        ⟨program 2, program 3⟩, rfl, ?_⟩
      · refine ⟨framing "B/wire" "", ⟨0, 1, 144115398529318913, "AB"⟩,
          by simp [inventory, peers], rfl, mka.payload, rfl, ?_, ?_, ?_⟩
        all_goals exact of_decide_eq_true rfl
      · exact captured_positive_MKA_and_data.2.1

end TDN.Imported.CompleteLinkHeaderFiltering

namespace TDN.Imported.CompleteLinkHeaderFiltering
open Compliance Targets Targets.Complete

tdn_data txA : LayeredFrame.MACsecAssociation from "../../data/evidence/proof010-link-header/InstalledAssociations-v2.json" ["ATx"]
tdn_data rxA : LayeredFrame.MACsecAssociation from "../../data/evidence/proof010-link-header/InstalledAssociations-v2.json" ["ARx"]
tdn_data txB : LayeredFrame.MACsecAssociation from "../../data/evidence/proof010-link-header/InstalledAssociations-v2.json" ["BTx"]
tdn_data rxB : LayeredFrame.MACsecAssociation from "../../data/evidence/proof010-link-header/InstalledAssociations-v2.json" ["BRx"]

def installedInventory (base : PacketProcessing.Inventory) : PacketProcessing.Inventory :=
  { inventory base with
    macsecTunnel := fun association => if association.sci = txA.sci then "AB" else "BA",
    configuration := { (inventory base).configuration with
      macIfaces := [
        { macIface 0 2 with transmitAssociation := some txA, receiveAssociations := [rxA] },
        { macIface 1 3 with transmitAssociation := some txB, receiveAssociations := [rxB] }] } }

def installedDeployment (base : Deployment) (processing : PacketProcessing.Inventory) : Deployment :=
  { deployment base processing with processing := some (installedInventory processing) }

instance (base : Deployment) (processing : PacketProcessing.Inventory) :
    DecidableRel (installedDeployment base processing).intendedPeer := by
  intro source destination
  change Decidable ((source, destination) ∈ [("A", "B"), ("B", "A")])
  infer_instance

theorem captured_installed_program_model_RG038
    (base : Deployment) (processing : PacketProcessing.Inventory) :
    msc_ip_header_and_multicast_filtering (installedDeployment base processing) (fun _ => false) := by
  apply ip_and_link_header_filtering_from_inventory_and_rule_atoms
    (installedDeployment base processing) (installedInventory processing) (fun _ => false)
  · intro _
    rfl
  · rfl
  · rfl
  · funext owner
    simp [installedDeployment, deployment, grayWorkstationRole, Deployment.IsDevice, devices]
  · rfl
  · rfl
  · funext iface address
    simp [installedDeployment, installedInventory, deployment, inventory, nativeLocalAddress, interfaces, Interface.HasLocalAddress]
  · rfl
  · rfl
  · unfold LinkPolicyRecordChecks Deployment.LinkPath
    dsimp [installedInventory, inventory, macIface]
    decide
  · exact of_decide_eq_true rfl
  · intro interface member endpoint endpointMember name packet framing destination
    change ((installedDeployment base processing).Observe packet).trafficClass = .control
    have records : MKAObservationRecords (installedDeployment base processing) endpoint.actorSCI := by
      simp [MKAObservationRecords, installedDeployment, deployment, devices]
    exact mka_observation_class _ packet endpoint.actorSCI records framing destination

lemma captured_installed_data_is_fully_admitted
    (base : Deployment) (processing : PacketProcessing.Inventory) :
    (installedDeployment base processing).Accepts "A/wire" .outbound
      ((installedDeployment base processing).Observe (dataFrame.Packet "" "A/wire")) ∧
    (installedDeployment base processing).Accepts "B/wire" .inbound
      ((installedDeployment base processing).Observe (dataFrame.Packet "B/wire" "")) := by
  have macsec : ∀ ingress egress, PacketMACsec (dataFrame.Packet ingress egress) := by
    intro ingress egress
    exact (show PacketMACsec (dataFrame.Packet "" "") from by decide)
  have supported : ∀ ingress egress,
      (installedDeployment base processing).Supported
        ((installedDeployment base processing).Observe (dataFrame.Packet ingress egress)) := by
    intro ingress egress
    refine ⟨rfl, ?_⟩
    change (installedDeployment base processing).ManagementMetadataBound (dataFrame.Packet ingress egress)
    unfold Deployment.ManagementMetadataBound
    have dataClass : PacketClass (dataFrame.Packet ingress egress) = .protectedData := by
      exact (show PacketClass (dataFrame.Packet "" "") = .protectedData from by decide)
    simp [dataClass]
  constructor
  · refine ⟨.link, supported "" "A/wire", ?_, ?_⟩
    · refine ⟨installedInventory processing, rfl, 0, by simp [installedInventory, inventory], rfl,
        interfaces[0], by simp [installedDeployment, installedInventory, deployment, interfaces], rfl, rfl, ?_⟩
      simp [PacketAtHook, HookDirection, installedDeployment, installedInventory, inventory, ifaceName,
        LinkAdmission.Frame.Packet, Deployment.Observe]
    · refine ⟨⟨installedInventory processing, rfl, 0, by simp [installedInventory, inventory], rfl,
        Or.inr (Or.inr ?_)⟩,
        installedInventory processing, rfl, 0, by simp [installedInventory, inventory], rfl,
        ⟨program 0, program 1⟩, rfl, ?_⟩
      · refine ⟨macsec "" "A/wire",
          { macIface 0 2 with transmitAssociation := some txA, receiveAssociations := [rxA] },
          by simp [installedInventory], rfl, txA, dataFrame.payload, rfl, ?_, ?_, ?_⟩
        all_goals exact of_decide_eq_true rfl
      · exact captured_positive_MKA_and_data.2.2.1
  · refine ⟨.link, supported "B/wire" "", ?_, ?_⟩
    · refine ⟨installedInventory processing, rfl, 1, by simp [installedInventory, inventory], rfl,
        interfaces[1], by simp [installedDeployment, installedInventory, deployment, interfaces], rfl, rfl, ?_⟩
      simp [PacketAtHook, HookDirection, installedDeployment, installedInventory, inventory, ifaceName,
        LinkAdmission.Frame.Packet, Deployment.Observe]
    · refine ⟨⟨installedInventory processing, rfl, 1, by simp [installedInventory, inventory], rfl,
        Or.inr (Or.inr ?_)⟩,
        installedInventory processing, rfl, 1, by simp [installedInventory, inventory], rfl,
        ⟨program 2, program 3⟩, rfl, ?_⟩
      · refine ⟨macsec "B/wire" "",
          { macIface 1 3 with transmitAssociation := some txB, receiveAssociations := [rxB] },
          by simp [installedInventory], rfl, rxB, dataFrame.payload, rfl, ?_, ?_, ?_⟩
        all_goals exact of_decide_eq_true rfl
      · exact captured_positive_MKA_and_data.2.2.2

lemma local_association_indices_are_distinct :
    txA.keyGeneration ≠ rxB.keyGeneration ∧ txB.keyGeneration ≠ rxA.keyGeneration := by decide

end TDN.Imported.CompleteLinkHeaderFiltering
