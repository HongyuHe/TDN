import TDN.Models.MultiProtocolForwarding

namespace TDN.MultiProtocolForwarding
open LayeredFrame

structure MACsecOutputChecks (config : Config) : Prop where
  secure : ∀ iface ∈ config.macIfaces,
    iface.settings.protectFrames = true ∧ iface.settings.encryptFrames = true ∧
      iface.settings.confidentialityOffset = 0
  uniquePhysical : ∀ first ∈ config.macIfaces, ∀ second ∈ config.macIfaces,
    first.physicalIface = second.physicalIface → first = second
  routedOutputs : ∀ route ∈ config.ip.routes, ∀ iface ∈ config.macIfaces,
    route.egress ≠ iface.physicalIface
  bridgeOutputs : ∀ first second, config.bridge first second →
    ∀ iface ∈ config.macIfaces, second ≠ iface.physicalIface

def MACsecOutputProtected (config : Config) (state : State) : Prop :=
  ((state.datapathStage = .routed ∨ state.datapathStage = .outputRouted ∨
      state.datapathStage = .filtered ∨ state.datapathStage = .encapsulated) →
    ∀ iface ∈ config.macIfaces, state.iface ≠ iface.physicalIface) ∧
  (state.datapathStage = .egressReady →
    ∀ iface ∈ config.macIfaces, state.iface = iface.physicalIface →
      ∃ association body, iface.transmitAssociation = some association ∧
        state.frame.body = .macsec association body)

lemma step_preserves_macsec_output_protection {config : Config}
    (checks : MACsecOutputChecks config) {before after : State} {action : Action}
    (step : Step config before action after) (safe : MACsecOutputProtected config before) :
    MACsecOutputProtected config after := by
  obtain ⟨processing, output⟩ := safe
  cases step with
  | route route stage visible selected entry | routeLocalOutput route stage visible selected entry =>
    exact ⟨fun _ iface member => checks.routedOutputs route selected.1 iface member,
      by simp [MACsecOutputProtected]⟩
  | routeOuterPacket route stage visible selected entry =>
    refine ⟨by simp, fun _ iface member same => ?_⟩
    exact False.elim (checks.routedOutputs route selected.1 iface member same)
  | forwardFilter stage visible accepted =>
    exact ⟨fun _ => processing (Or.inl stage), by simp⟩
  | outputFilter stage visible accepted =>
    exact ⟨fun _ => processing (Or.inr (Or.inl stage)), by simp⟩
  | encryptIPsec policy association stage visible selected installed bound =>
    exact ⟨fun _ => processing (Or.inr (Or.inr (Or.inl stage))), by simp⟩
  | forwardWithoutEncap stage visible noPolicy =>
    refine ⟨by simp, fun _ iface member same => ?_⟩
    exact False.elim ((processing (Or.inr (Or.inr (Or.inl stage))) iface member) same)
  | bridge next stage member | bridgeOutput next stage member =>
    refine ⟨by simp, fun _ iface present same => ?_⟩
    exact False.elim (checks.bridgeOutputs _ _ member iface present same)
  | encryptMACsec iface association configured stage logical emits =>
    refine ⟨?_, ?_⟩
    · intro forbidden
      simp [stage] at forbidden
    · intro _ other member same
      have equal : iface = other := checks.uniquePhysical iface configured other member same
      subst other
      exact ⟨association, before.frame.body, emits.1, Config.macsecFrame_body config before.frame association⟩
  | unprotectedMACsec iface configured stage logical enabled unprotected =>
    simp [(checks.secure iface configured).1] at unprotected
  | protectMACsec iface association configured stage logical enabled protection installed limited =>
    obtain ⟨_, encrypt, zero⟩ := checks.secure iface configured
    rcases limited with impossible | impossible
    · simp [encrypt] at impossible
    · exact False.elim (impossible zero)
  | decryptMACsec iface association transmitted body configured stage =>
    simp [MACsecOutputProtected, stage]
  | validateMACsec iface association transmitted encryptFrames confidentialityOffset body configured stage =>
    simp [MACsecOutputProtected, stage]
  | uncheckedMACsec iface configured stage =>
    simp [MACsecOutputProtected, stage]
  | receive | decryptIPsec | inputFilter | deliver | deliverEthernet |
      linkTransmit | encapsulate | decapsulate | drop =>
    simp [MACsecOutputProtected]

lemma link_transmit_uses_ready_output {config : Config} {before after : State}
    (step : Step config before .linkTransmit after) :
    before.datapathStage = .egressReady ∧ config.physicalLink before.iface after.iface := by
  cases step with
  | linkTransmit next ready linked => exact ⟨ready, linked⟩

theorem forwarding_preserves_macsec_output_protection (config : Config)
    (checks : MACsecOutputChecks config) {start finish : State} {actions : List Action}
    (run : ForwardsAlongTrace config start actions finish)
    (initial : MACsecOutputProtected config start) : MACsecOutputProtected config finish := by
  have preserved : (lts config).TrInv (MACsecOutputProtected config) :=
    fun _ _ _ step safe => step_preserves_macsec_output_protection checks step safe
  exact Cslib.LTS.mtrInv_of_trInv preserved start actions finish run initial

structure MACsecWireChecks (config : Config) : Prop where
  output : MACsecOutputChecks config
  logicalSeparation : ∀ first ∈ config.macIfaces, ∀ second ∈ config.macIfaces,
    first.logicalIface ≠ second.physicalIface
  linkSources : ∀ first second, config.physicalLink first second →
    ∀ receiver ∈ config.macIfaces, receiver.physicalIface = second →
    ∃ sender ∈ config.macIfaces, sender.physicalIface = first
  noCarriers : config.carriers = []

def PhysicalMACsecFrames (config : Config) (state : State) : Prop :=
  ∀ iface ∈ config.macIfaces, state.iface = iface.physicalIface →
    ∃ sender ∈ config.macIfaces, ∃ association body,
      sender.transmitAssociation = some association ∧ state.frame.body = .macsec association body

lemma step_preserves_physical_macsec_frames {config : Config} (checks : MACsecWireChecks config)
    {before after : State} {action : Action} (step : Step config before action after)
    (output : MACsecOutputProtected config before) (framed : PhysicalMACsecFrames config before) :
    PhysicalMACsecFrames config after := by
  cases step with
  | route route stage visible selected entry | routeLocalOutput route stage visible selected entry | routeOuterPacket route stage visible selected entry =>
    intro iface member same
    exact False.elim (checks.output.routedOutputs route selected.1 iface member same)
  | bridge next stage linked | bridgeOutput next stage linked =>
    intro iface member same
    exact False.elim (checks.output.bridgeOutputs _ _ linked iface member same)
  | encryptIPsec policy association stage =>
    intro iface member same
    exact False.elim (output.1 (Or.inr (Or.inr (Or.inl stage))) iface member same)
  | decryptIPsec policy association body header stage encrypted =>
    intro iface member same
    obtain ⟨sender, configured, mac, contents, installed, protectedBody⟩ := framed iface member same
    rw [protectedBody] at encrypted
    cases encrypted
  | encryptMACsec iface association configured =>
    intro other member same
    exact ⟨iface, configured, association, before.frame.body, ‹fullMACsecTransmit _ _ _›.1,
      Config.macsecFrame_body _ _ _⟩
  | unprotectedMACsec iface configured stage logical enabled unprotected =>
    simp [(checks.output.secure iface configured).1] at unprotected
  | protectMACsec iface association configured stage logical enabled protection installed limited =>
    obtain ⟨_, encrypt, zero⟩ := checks.output.secure iface configured
    rcases limited with impossible | impossible
    · simp [encrypt] at impossible
    · exact False.elim (impossible zero)
  | decryptMACsec iface association transmitted body configured | validateMACsec iface association transmitted encryptFrames confidentialityOffset body configured | uncheckedMACsec iface configured =>
    intro other member same
    exact False.elim (checks.logicalSeparation iface configured other member same)
  | linkTransmit next stage linked =>
    intro receiver member same
    obtain ⟨sender, configured, physical⟩ := checks.linkSources _ _ linked receiver member same.symm
    exact framed sender configured physical.symm
  | encapsulate iface configured | decapsulate iface body configured =>
    simp [checks.noCarriers] at configured
  | receive | forwardFilter | outputFilter | forwardWithoutEncap | inputFilter |
      deliver | deliverEthernet | drop => exact framed

end TDN.MultiProtocolForwarding
