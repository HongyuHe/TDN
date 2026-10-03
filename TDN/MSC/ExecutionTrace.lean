import TDN.MSC.Execution
import TDN.Network.ExecutionTrace

/-!
Executable trace witnesses show that the safety relation admits the intended
data paths. Each forwarding command evaluates the observed FIB, actual filter,
and XFRM policy/SA selection. Failed commands return `none`. A proved runner
lemma converts successful evaluation into an execution of the same relation
used by the arbitrary-path protection theorem.
-/
namespace TDN.MSC.ExecutionTrace
open TDN.Network TDN.Network.Execution
open TDN.MSC.Execution
variable {Message : Type}

instance : DecidableRel model.linked := fun a b =>
  inferInstanceAs (Decidable ((a, b) ∈ wires))

instance : DecidableRel model.bridge := fun a b =>
  inferInstanceAs (Decidable ((a, b) ∈ bridges))

/-- The concrete experiment reuses the deployment-independent trace runner. -/
abbrev Command := TDN.Network.ExecutionTrace.Command String

abbrev advance (state : State String Message) (command : Command) : Option (State String Message) :=
  TDN.Network.ExecutionTrace.advance model state command

abbrev run (state : State String Message) (commands : List Command) : Option (State String Message) :=
  TDN.Network.ExecutionTrace.run model state commands

abbrev trace (state : State String Message) (commands : List Command) :
    Option (TDN.Network.ExecutionTrace.Result String Message) :=
  TDN.Network.ExecutionTrace.trace model state commands

theorem advance_is_step (before after : State String Message) (command : Command)
    (accepted : advance before command = some after) : Step model before after :=
  TDN.Network.ExecutionTrace.advance_is_step model before after command accepted

theorem run_is_execution (before after : State String Message) (commands : List Command)
    (accepted : run before commands = some after) : Reach (Step model) before after :=
  TDN.Network.ExecutionTrace.run_is_execution model before after commands accepted

def hostAddress (host : String) : UInt32 :=
  (((device? host).bind fun device => device.interfaces.find? (fun i => i.zone == .red)).bind
    fun interface => (TDN.MSC.Prefix.parse? interface.address).map TDN.MSC.Prefix.address).getD 0

def start (source destination : String) : State String Unit :=
  let header : IPv4Header :=
    { source := hostAddress source, destination := hostAddress destination,
      protocol := 1, bytes := 100 }
  ⟨⟨source, "red"⟩, .output, .clear header (some ())⟩

def dataCommands (sourceSite targetSite level : String) : List Command :=
  let origin := sourceSite ++ level
  let target := targetSite ++ level
  let blackSource := "p" ++ (if sourceSite == "A" then "1" else "2") ++ level
  [ .wire ⟨"I_" ++ origin, "red"⟩, .forward,
    .wire ⟨"G_" ++ origin, "inner"⟩, .switch "outer",
    .wire ⟨"O_" ++ origin, "gray"⟩, .forward,
    .wire ⟨"OF_" ++ origin, "inside"⟩, .forward,
    .wire ⟨"BLACK", blackSource⟩, .forward,
    .wire ⟨"OF_" ++ target, "outside"⟩, .forward,
    .wire ⟨"O_" ++ target, "black"⟩, .forward,
    .wire ⟨"G_" ++ target, "outer"⟩, .switch "inner",
    .wire ⟨"I_" ++ target, "gray"⟩, .forward,
    .wire ⟨"R_" ++ target, "red"⟩ ]

def witnessedPairs : List (String × String × String) :=
  [("A", "B", "1"), ("A", "B", "2"), ("B", "A", "1"), ("B", "A", "2")]

/-- Every intended host direction has a full admitted trace ending at the
remote Red host with the original message and both IPsec layers removed. -/
theorem all_four_directions_reach_remote_red : ∀ choice ∈ witnessedPairs,
    let source := "R_" ++ choice.1 ++ choice.2.2
    let target := "R_" ++ choice.2.1 ++ choice.2.2
    let result := run (start source target) (dataCommands choice.1 choice.2.1 choice.2.2)
    result.isSome = true ∧ result.all (fun state =>
      state.location == ⟨target, "red"⟩ && state.phase == .input &&
      state.packet.message == some () && state.packet.depth == 0) = true := by decide

theorem all_four_directions_pass_host_input : ∀ choice ∈ witnessedPairs,
    let source := "R_" ++ choice.1 ++ choice.2.2
    let target := "R_" ++ choice.2.1 ++ choice.2.2
    ((run (start source target) (dataCommands choice.1 choice.2.1 choice.2.2)).bind fun state =>
      model.deliver state.location.node state.location.port state.packet).isSome = true := by decide

/-- Inner IKE is an explicit control exception. Its clear Gray packet gains
one outer layer on Black and carries no protected application message. -/
def innerIKE : State String Unit :=
  let header : IPv4Header :=
    { source := 0x0a640102, destination := 0x0ac80102,
      protocol := 17, destinationPort := 500, bytes := 100 }
  ⟨⟨"I_A1", "gray"⟩, .output, .clear header none⟩

theorem inner_ike_control_is_allowed_on_black :
    model.outputFilter "I_A1" "gray" innerIKE.packet.header = true ∧
    let reached := run innerIKE [.wire ⟨"G_A1", "inner"⟩, .switch "outer", .wire ⟨"O_A1", "gray"⟩, .forward]
    reached.isSome = true ∧ reached.all (fun state =>
      state.location == ⟨"O_A1", "black"⟩ && state.packet.depth == 1 && state.packet.message.isNone) = true := by decide

end TDN.MSC.ExecutionTrace
