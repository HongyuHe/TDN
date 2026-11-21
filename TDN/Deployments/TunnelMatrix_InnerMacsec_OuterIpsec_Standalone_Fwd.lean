import TDN.Import.SnapshotLoader
import TDN.Deployments.TunnelMatrix_EncapStackChecks

namespace TDN.Deployments.PairingMacsecIpsecStandalone.Forward
open MultiProtocolForwarding LayeredFrame
set_option maxRecDepth 1000000
set_option linter.unusedSimpArgs false

load_network_records usefulState0 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState0"]

load_network_records usefulState1 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState1"]

load_network_records usefulState2 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState2"]

load_network_records usefulState3 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState3"]

load_network_records usefulState4 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState4"]

load_network_records usefulState5 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState5"]

load_network_records usefulState6 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState6"]

load_network_records usefulState7 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState7"]

load_network_records usefulState8 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState8"]

load_network_records usefulState9 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState9"]

load_network_records usefulState10 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState10"]

load_network_records usefulState11 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState11"]

load_network_records usefulState12 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState12"]

load_network_records usefulState13 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState13"]

load_network_records usefulState14 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState14"]

load_network_records usefulState15 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState15"]

load_network_records usefulState16 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState16"]

load_network_records usefulState17 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState17"]

load_network_records usefulState18 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState18"]

load_network_records usefulState19 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState19"]

load_network_records usefulState20 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState20"]

load_network_records usefulState21 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState21"]

load_network_records usefulState22 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState22"]

load_network_records usefulState23 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState23"]

load_network_records usefulState24 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState24"]

load_network_records usefulState25 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState25"]

load_network_records usefulState26 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState26"]

load_network_records usefulState27 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState27"]

load_network_records usefulState28 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState28"]

load_network_records usefulState29 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState29"]

load_network_records usefulState30 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState30"]

load_network_records usefulState31 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState31"]

load_network_records usefulState32 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState32"]

load_network_records usefulState33 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState33"]

load_network_records usefulState34 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState34"]

load_network_records usefulState35 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState35"]

load_network_records usefulState36 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState36"]

load_network_records usefulState37 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState37"]

load_network_records usefulState38 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState38"]

load_network_records usefulState39 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState39"]

load_network_records usefulState40 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState40"]

load_network_records usefulState41 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState41"]

load_network_records usefulState42 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState42"]

load_network_records usefulState43 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState43"]

load_network_records usefulState44 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState44"]

load_network_records usefulState45 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState45"]

load_network_records usefulState46 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState46"]

load_network_records usefulState47 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState47"]

load_network_records usefulState48 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState48"]

load_network_records usefulState49 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState49"]

load_network_records usefulState50 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState50"]

load_network_records usefulState51 : MultiProtocolForwarding.TunnelForwardingState from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulState51"]

lemma useful_step0 : MultiProtocolForwarding.TunnelForwardingStep config usefulState0 .route usefulState1 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.routeLocalOutput ⟨18, 18, 167903232, 167903487, 24, 0, 32766⟩ rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide) rfl

lemma useful_step1 : MultiProtocolForwarding.TunnelForwardingStep config usefulState1 .outputFilter usefulState2 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.outputFilter rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step2 : MultiProtocolForwarding.TunnelForwardingStep config usefulState2 .forwardWithoutEncap usefulState3 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.forwardWithoutEncap rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step3 : MultiProtocolForwarding.TunnelForwardingStep config usefulState3 .linkTransmit usefulState4 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.linkTransmit 24 rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step4 : MultiProtocolForwarding.TunnelForwardingStep config usefulState4 .receive usefulState5 := by
  exact TunnelForwardingStep.receive rfl rfl "NEW"

lemma useful_step5 : MultiProtocolForwarding.TunnelForwardingStep config usefulState5 .route usefulState6 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.route ⟨24, 23, 167903232, 167903487, 24, 0, 32766⟩ rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide) rfl

lemma useful_step6 : MultiProtocolForwarding.TunnelForwardingStep config usefulState6 .forwardFilter usefulState7 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.forwardFilter rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step7 : MultiProtocolForwarding.TunnelForwardingStep config usefulState7 .forwardWithoutEncap usefulState8 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.forwardWithoutEncap rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step8 : MultiProtocolForwarding.TunnelForwardingStep config usefulState8 .encryptMACsec usefulState9 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.encryptMACsec (macIfaces[0]'(by native_decide)) ⟨1, 778884615472676865, 0, 0⟩ (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide) rfl rfl ⟨rfl, rfl⟩

lemma useful_step9 : MultiProtocolForwarding.TunnelForwardingStep config usefulState9 .linkTransmit usefulState10 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.linkTransmit 2 rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step10 : MultiProtocolForwarding.TunnelForwardingStep config usefulState10 .bridge usefulState11 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.bridge 3 rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step11 : MultiProtocolForwarding.TunnelForwardingStep config usefulState11 .encapsulate usefulState12 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.encapsulate (carriers[0]'(by native_decide)) (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide) rfl rfl

lemma useful_step12 : MultiProtocolForwarding.TunnelForwardingStep config usefulState12 .route usefulState13 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.routeLocalOutput ⟨5, 5, 169148417, 169148417, 32, 0, 32766⟩ rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide) rfl

lemma useful_step13 : MultiProtocolForwarding.TunnelForwardingStep config usefulState13 .outputFilter usefulState14 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.outputFilter rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step14 : MultiProtocolForwarding.TunnelForwardingStep config usefulState14 .forwardWithoutEncap usefulState15 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.forwardWithoutEncap rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step15 : MultiProtocolForwarding.TunnelForwardingStep config usefulState15 .linkTransmit usefulState16 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.linkTransmit 30 rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step16 : MultiProtocolForwarding.TunnelForwardingStep config usefulState16 .receive usefulState17 := by
  exact TunnelForwardingStep.receive rfl rfl "NEW"

lemma useful_step17 : MultiProtocolForwarding.TunnelForwardingStep config usefulState17 .route usefulState18 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.route ⟨30, 29, 0, 4294967295, 0, 0, 32766⟩ rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide) rfl

lemma useful_step18 : MultiProtocolForwarding.TunnelForwardingStep config usefulState18 .forwardFilter usefulState19 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.forwardFilter rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step19 : MultiProtocolForwarding.TunnelForwardingStep config usefulState19 .encryptIPsec usefulState20 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.encryptIPsec ⟨200, 2, 3221225985, 3221226241, 168493057, 168493057, 169148417, 169148417, 0, none⟩ ⟨200, 2001, 3221225985, 3221226241⟩ rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide) (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide) (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step20 : MultiProtocolForwarding.TunnelForwardingStep config usefulState20 .route usefulState21 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.routeOuterPacket ⟨29, 29, 0, 4294967295, 0, 0, 32766⟩ rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide) rfl

lemma useful_step21 : MultiProtocolForwarding.TunnelForwardingStep config usefulState21 .linkTransmit usefulState22 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.linkTransmit 11 rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step22 : MultiProtocolForwarding.TunnelForwardingStep config usefulState22 .receive usefulState23 := by
  exact TunnelForwardingStep.receive rfl rfl "NEW"

lemma useful_step23 : MultiProtocolForwarding.TunnelForwardingStep config usefulState23 .route usefulState24 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.route ⟨11, 13, 3221226240, 3221226243, 30, 0, 32766⟩ rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide) rfl

lemma useful_step24 : MultiProtocolForwarding.TunnelForwardingStep config usefulState24 .forwardFilter usefulState25 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.forwardFilter rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step25 : MultiProtocolForwarding.TunnelForwardingStep config usefulState25 .forwardWithoutEncap usefulState26 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.forwardWithoutEncap rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step26 : MultiProtocolForwarding.TunnelForwardingStep config usefulState26 .linkTransmit usefulState27 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.linkTransmit 16 rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step27 : MultiProtocolForwarding.TunnelForwardingStep config usefulState27 .receive usefulState28 := by
  exact TunnelForwardingStep.receive rfl rfl "NEW"

lemma useful_step28 : MultiProtocolForwarding.TunnelForwardingStep config usefulState28 .route usefulState29 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.route ⟨16, 14, 3221226240, 3221226243, 30, 0, 32766⟩ rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide) rfl

lemma useful_step29 : MultiProtocolForwarding.TunnelForwardingStep config usefulState29 .forwardFilter usefulState30 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.forwardFilter rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step30 : MultiProtocolForwarding.TunnelForwardingStep config usefulState30 .forwardWithoutEncap usefulState31 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.forwardWithoutEncap rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step31 : MultiProtocolForwarding.TunnelForwardingStep config usefulState31 .linkTransmit usefulState32 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.linkTransmit 32 rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step32 : MultiProtocolForwarding.TunnelForwardingStep config usefulState32 .decryptIPsec usefulState33 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.decryptIPsec ⟨200, 2, 3221225985, 3221226241, 168493057, 168493057, 169148417, 169148417, 0, none⟩ ⟨200, 2001, 3221225985, 3221226241⟩ (.carrier ⟨168493057, 169148417, 1701, 1701, 200, "l2tpv3", "udp"⟩ (.macsec ⟨1, 778884615472676865, 0, 0⟩ (.datagram { source := 167837698, destination := 167903234, protocol := "icmp", ingress := "", egress := "", sourcePort := 0, destinationPort := 0, ipv4HeaderWords := 5, ipv6NextHeader := 0, matchedInboundPolicyIds := [], matchedOutboundPolicyIds := [], connectionState := "" }))) { source := 168493057, destination := 169148417, protocol := "udp", ingress := "", egress := "", sourcePort := 1701, destinationPort := 1701, ipv4HeaderWords := 5, ipv6NextHeader := 0, matchedInboundPolicyIds := [], matchedOutboundPolicyIds := [], connectionState := "" } rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide) (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide) (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide) rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide) "NEW"

lemma useful_step33 : MultiProtocolForwarding.TunnelForwardingStep config usefulState33 .route usefulState34 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.route ⟨32, 33, 169148416, 169148419, 30, 0, 32766⟩ rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide) rfl

lemma useful_step34 : MultiProtocolForwarding.TunnelForwardingStep config usefulState34 .forwardFilter usefulState35 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.forwardFilter rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step35 : MultiProtocolForwarding.TunnelForwardingStep config usefulState35 .forwardWithoutEncap usefulState36 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.forwardWithoutEncap rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step36 : MultiProtocolForwarding.TunnelForwardingStep config usefulState36 .linkTransmit usefulState37 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.linkTransmit 10 rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step37 : MultiProtocolForwarding.TunnelForwardingStep config usefulState37 .receive usefulState38 := by
  exact TunnelForwardingStep.receive rfl rfl "NEW"

lemma useful_step38 : MultiProtocolForwarding.TunnelForwardingStep config usefulState38 .inputFilter usefulState39 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.inputFilter rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide) (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step39 : MultiProtocolForwarding.TunnelForwardingStep config usefulState39 .decapsulate usefulState40 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.decapsulate (carriers[1]'(by native_decide)) (.macsec ⟨1, 778884615472676865, 0, 0⟩ (.datagram { source := 167837698, destination := 167903234, protocol := "icmp", ingress := "", egress := "", sourcePort := 0, destinationPort := 0, ipv4HeaderWords := 5, ipv6NextHeader := 0, matchedInboundPolicyIds := [], matchedOutboundPolicyIds := [], connectionState := "" })) (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide) rfl rfl rfl

lemma useful_step40 : MultiProtocolForwarding.TunnelForwardingStep config usefulState40 .bridge usefulState41 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.bridge 7 rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step41 : MultiProtocolForwarding.TunnelForwardingStep config usefulState41 .linkTransmit usefulState42 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.linkTransmit 25 rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step42 : MultiProtocolForwarding.TunnelForwardingStep config usefulState42 .decryptMACsec usefulState43 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.decryptMACsec (macIfaces[1]'(by native_decide)) ⟨1, 778884615472676865, 0, 0⟩ ⟨1, 778884615472676865, 0, 0⟩ (.datagram { source := 167837698, destination := 167903234, protocol := "icmp", ingress := "", egress := "", sourcePort := 0, destinationPort := 0, ipv4HeaderWords := 5, ipv6NextHeader := 0, matchedInboundPolicyIds := [], matchedOutboundPolicyIds := [], connectionState := "" }) (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide) rfl rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide) (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step43 : MultiProtocolForwarding.TunnelForwardingStep config usefulState43 .receive usefulState44 := by
  exact TunnelForwardingStep.receive rfl rfl "NEW"

lemma useful_step44 : MultiProtocolForwarding.TunnelForwardingStep config usefulState44 .route usefulState45 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.route ⟨27, 28, 167903232, 167903487, 24, 0, 32766⟩ rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide) rfl

lemma useful_step45 : MultiProtocolForwarding.TunnelForwardingStep config usefulState45 .forwardFilter usefulState46 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.forwardFilter rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step46 : MultiProtocolForwarding.TunnelForwardingStep config usefulState46 .forwardWithoutEncap usefulState47 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.forwardWithoutEncap rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step47 : MultiProtocolForwarding.TunnelForwardingStep config usefulState47 .linkTransmit usefulState48 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.linkTransmit 20 rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step48 : MultiProtocolForwarding.TunnelForwardingStep config usefulState48 .receive usefulState49 := by
  exact TunnelForwardingStep.receive rfl rfl "NEW"

lemma useful_step49 : MultiProtocolForwarding.TunnelForwardingStep config usefulState49 .inputFilter usefulState50 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.inputFilter rfl rfl (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide) (by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, PacketPolicy.AclAllows, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)

lemma useful_step50 : MultiProtocolForwarding.TunnelForwardingStep config usefulState50 .deliver usefulState51 := by
  exact MultiProtocolForwarding.TunnelForwardingStep.deliver 1 rfl rfl rfl

load_network_records bridgeRules10 : List PacketPolicy.PacketAclRule from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.bridgeRules10"]

load_network_records bridgePacket10 : PacketPolicy.Packet from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.bridgePacket10"]

lemma positive_bridge_filter10 : PacketPolicy.AclAllows bridgeRules10 .deny bridgePacket10 := by
  unfold PacketPolicy.AclAllows bridgeRules10 bridgePacket10; native_decide

load_network_records bridgeRules40 : List PacketPolicy.PacketAclRule from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.bridgeRules40"]

load_network_records bridgePacket40 : PacketPolicy.Packet from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.bridgePacket40"]

lemma positive_bridge_filter40 : PacketPolicy.AclAllows bridgeRules40 .deny bridgePacket40 := by
  unfold PacketPolicy.AclAllows bridgeRules40 bridgePacket40; native_decide

load_network_records usefulActions : List MultiProtocolForwarding.TunnelForwardingAction from "../../data/evidence/spec009-header-state/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/spec002-state-entry/TunnelMatrix_InnerMacsec_OuterIpsec_Standalone_Fwd.json" ["TDN.Deployments.PairingMacsecIpsecStandalone.Forward.usefulActions"]

theorem positive_mixed_delivery : (lts config).MTr usefulState0 usefulActions usefulState51 := by
  exact Cslib.LTS.MTr.stepL useful_step0 (Cslib.LTS.MTr.stepL useful_step1 (Cslib.LTS.MTr.stepL useful_step2 (Cslib.LTS.MTr.stepL useful_step3 (Cslib.LTS.MTr.stepL useful_step4 (Cslib.LTS.MTr.stepL useful_step5 (Cslib.LTS.MTr.stepL useful_step6 (Cslib.LTS.MTr.stepL useful_step7 (Cslib.LTS.MTr.stepL useful_step8 (Cslib.LTS.MTr.stepL useful_step9 (Cslib.LTS.MTr.stepL useful_step10 (Cslib.LTS.MTr.stepL useful_step11 (Cslib.LTS.MTr.stepL useful_step12 (Cslib.LTS.MTr.stepL useful_step13 (Cslib.LTS.MTr.stepL useful_step14 (Cslib.LTS.MTr.stepL useful_step15 (Cslib.LTS.MTr.stepL useful_step16 (Cslib.LTS.MTr.stepL useful_step17 (Cslib.LTS.MTr.stepL useful_step18 (Cslib.LTS.MTr.stepL useful_step19 (Cslib.LTS.MTr.stepL useful_step20 (Cslib.LTS.MTr.stepL useful_step21 (Cslib.LTS.MTr.stepL useful_step22 (Cslib.LTS.MTr.stepL useful_step23 (Cslib.LTS.MTr.stepL useful_step24 (Cslib.LTS.MTr.stepL useful_step25 (Cslib.LTS.MTr.stepL useful_step26 (Cslib.LTS.MTr.stepL useful_step27 (Cslib.LTS.MTr.stepL useful_step28 (Cslib.LTS.MTr.stepL useful_step29 (Cslib.LTS.MTr.stepL useful_step30 (Cslib.LTS.MTr.stepL useful_step31 (Cslib.LTS.MTr.stepL useful_step32 (Cslib.LTS.MTr.stepL useful_step33 (Cslib.LTS.MTr.stepL useful_step34 (Cslib.LTS.MTr.stepL useful_step35 (Cslib.LTS.MTr.stepL useful_step36 (Cslib.LTS.MTr.stepL useful_step37 (Cslib.LTS.MTr.stepL useful_step38 (Cslib.LTS.MTr.stepL useful_step39 (Cslib.LTS.MTr.stepL useful_step40 (Cslib.LTS.MTr.stepL useful_step41 (Cslib.LTS.MTr.stepL useful_step42 (Cslib.LTS.MTr.stepL useful_step43 (Cslib.LTS.MTr.stepL useful_step44 (Cslib.LTS.MTr.stepL useful_step45 (Cslib.LTS.MTr.stepL useful_step46 (Cslib.LTS.MTr.stepL useful_step47 (Cslib.LTS.MTr.stepL useful_step48 (Cslib.LTS.MTr.stepL useful_step49 (Cslib.LTS.MTr.stepL useful_step50 (Cslib.LTS.MTr.refl)))))))))))))))))))))))))))))))))))))))))))))))))))

lemma useful_red_origin : Requirements.MultiProtocolRedOrigin redSources usefulState0 := by
  simp [Requirements.MultiProtocolRedOrigin, usefulState0, redSources]

lemma useful_plaintext_delivery : usefulState51.datapathStage = .delivered ∧
    usefulState51.frame.body.protectionLayers = [] := ⟨rfl, rfl⟩
end TDN.Deployments.PairingMacsecIpsecStandalone.Forward
