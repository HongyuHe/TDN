import TDN.Models.PrerequisiteEventHistory
import Lean.Elab.Tactic.Omega

namespace TDN.SequenceFreshness

structure Transmission where
  association : Nat
  generation : Nat
  packetNumber : Nat
  sentAt : Nat
  deriving DecidableEq, Repr

structure Sample where
  association : Nat
  generation : Nat
  nextPacketNumber : Nat
  sampledAt : Nat
  deriving DecidableEq, Repr

def SameCounter (packet : Transmission) (sample : Sample) : Prop :=
  packet.association = sample.association ∧ packet.generation = sample.generation

def CounterSampleValid (history : List Transmission) (sample : Sample) : Prop :=
  ∀ packet ∈ history, SameCounter packet sample → packet.sentAt < sample.sampledAt →
    packet.packetNumber < sample.nextPacketNumber

def accepts (installedNext replayWindow : Nat) (packet : Transmission) : Bool :=
  decide (installedNext - replayWindow ≤ packet.packetNumber)

theorem accepted_transmission_is_recent (history : List Transmission) (sample : Sample)
    (packet : Transmission) (now maximumAge installedNext : Nat)
    (valid : CounterSampleValid history sample)
    (recorded : packet ∈ history) (same : SameCounter packet sample)
    (installed : sample.nextPacketNumber ≤ installedNext)
    (freshSample : now ≤ sample.sampledAt + maximumAge)
    (accepted : accepts installedNext 0 packet = true) :
    now ≤ packet.sentAt + maximumAge := by
  have lower : installedNext ≤ packet.packetNumber := by
    simpa [accepts] using accepted
  by_cases earlier : packet.sentAt < sample.sampledAt
  · have old := valid packet recorded same earlier
    omega
  · omega

def InstallMatches (sample : Sample) (installation : Sample) : Prop :=
  sample.association = installation.association ∧
  sample.generation = installation.generation ∧
  sample.nextPacketNumber = installation.nextPacketNumber ∧
  sample.sampledAt ≤ installation.sampledAt

theorem installed_samples_have_matching_updates (history actions : List Sample)
    (isInstall : Sample → Prop)
    (run : (Admission.lts isInstall InstallMatches).MTr [] actions history) :
    ∀ installation ∈ history, isInstall installation →
      ∃ sample ∈ history, InstallMatches sample installation :=
  Admission.all_admitted_events_have_prerequisites _ _ run

end TDN.SequenceFreshness
