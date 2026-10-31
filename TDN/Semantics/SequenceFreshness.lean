import TDN.Semantics.Admission
import Lean.Elab.Tactic.Omega

namespace TDN.SequenceFreshness

/-- Time uses physical milliseconds on one monotone timeline. Association and generation
identify one non-wrapping sequence-number space. -/
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

/-- The sender's sample reports the next unused number in its actual counter space. -/
def CounterSampleValid (history : List Transmission) (sample : Sample) : Prop :=
  ∀ packet ∈ history, SameCounter packet sample → packet.sentAt < sample.sampledAt →
    packet.packetNumber < sample.nextPacketNumber

/-- Zero replay window makes the installed next-PN field the receive lower threshold. -/
def accepts (installedNext replayWindow : Nat) (packet : Transmission) : Bool :=
  decide (installedNext - replayWindow ≤ packet.packetNumber)

/-- A receiver using a sufficiently recent authenticated counter sample cannot accept an
older transmission. The same association and generation exclude unrelated SA updates.
Control delivery freshness and the counter contract are explicit local premises. -/
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

/-- A stale or unrelated sample cannot silently supply the receive-side premise. -/
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
