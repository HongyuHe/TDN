import Cslib.Foundations.Semantics.LTS.Basic
import Mathlib.Data.List.Basic
import Lean.Elab.Tactic.Omega

namespace TDN.CoverTraffic

/-- A fixed record includes a header, one queued payload when available, and padding.
Time is measured in integer nanoseconds on a monotone clock. The queue limit counts
packets. These parameters describe a particular sender, independently of its topology. -/
structure Config where
  recordBytes : Nat
  headerBytes : Nat
  queueLimit : Nat
  intervalNs : Nat
  deriving DecidableEq, Repr

def Config.Valid (c : Config) : Prop :=
  c.headerBytes ≤ c.recordBytes ∧ 0 < c.queueLimit ∧ 0 < c.intervalNs

instance (c : Config) : Decidable c.Valid := by
  unfold Config.Valid
  infer_instance

abbrev Packet := List UInt8

def QueueValid (c : Config) (queue : List Packet) : Prop :=
  queue.length ≤ c.queueLimit ∧
  ∀ packet ∈ queue, packet.length ≤ c.recordBytes - c.headerBytes

/-- Oversized arrivals and arrivals at a full queue are dropped. An empty TUN read
does not enqueue a packet. Existing packets keep their FIFO order. -/
def enqueue (c : Config) (queue : List Packet) (packet : Packet) : List Packet :=
  if packet ≠ [] ∧ packet.length ≤ c.recordBytes - c.headerBytes ∧
      queue.length < c.queueLimit then queue ++ [packet] else queue

def payload (queue : List Packet) : Packet :=
  match queue with
  | [] => []
  | first :: _ => first

/-- The record's header is included in its length. Header field correctness and
encryption of the resulting bytes are separate implementation obligations. -/
def paddedBytes (c : Config) (packet : Packet) : Nat :=
  c.headerBytes + packet.length + (c.recordBytes - c.headerBytes - packet.length)

lemma padding_gives_fixed_length {c : Config} (valid : c.Valid)
    {packet : Packet} (fits : packet.length ≤ c.recordBytes - c.headerBytes) :
    paddedBytes c packet = c.recordBytes := by
  unfold paddedBytes
  have := valid.1
  omega

lemma enqueue_preserves_queue {c : Config} {queue : List Packet}
    (valid : QueueValid c queue) (packet : Packet) :
    QueueValid c (enqueue c queue packet) := by
  unfold enqueue
  split
  · rename_i accepted
    constructor
    · simp only [List.length_append, List.length_singleton]
      omega
    · intro p member
      rcases List.mem_append.mp member with old | new
      · exact valid.2 p old
      · have same := List.mem_singleton.mp new
        subst p
        exact accepted.2.1
  · exact valid

lemma tail_preserves_queue {c : Config} {queue : List Packet}
    (valid : QueueValid c queue) : QueueValid c queue.tail := by
  cases queue with
  | nil => simpa using valid
  | cons first rest =>
    constructor
    · simp only [List.tail_cons]
      have bound := valid.1
      simp only [List.length_cons] at bound
      omega
    · intro p member
      exact valid.2 p (List.mem_cons_of_mem first member)

lemma payload_fits {c : Config} {queue : List Packet}
    (valid : QueueValid c queue) :
    (payload queue).length ≤ c.recordBytes - c.headerBytes := by
  cases queue with
  | nil => simp [payload]
  | cons first rest => exact valid.2 first (List.mem_cons_self ..)

/-- One record describes one send attempt. A failed link still consumes the selected
queued packet in the retained sender implementation. A successful attempt alone does
not imply remote delivery. The time and success outcome are supplied by the environment. -/
structure Attempt where
  atNs : Nat
  bytes : Nat
  succeeded : Bool
  deriving DecidableEq, Repr

structure State where
  queue : List Packet
  attempts : List Attempt
  deadlineNs : Nat
  sequence : Nat
  deriving Repr

def initial (firstDeadline : Nat) : State := ⟨[], [], firstDeadline, 0⟩

/-- A late sender skips elapsed slots. It does not emit a burst to catch up. The
completion clock sample follows the send call. Float-clock rounding in Python is
part of the implementation correspondence, not an unconditional timing guarantee. -/
def nextDeadline (c : Config) (previous completed : Nat) : Nat :=
  if previous + c.intervalNs < completed then completed + c.intervalNs
  else previous + c.intervalNs

lemma deadline_advances (c : Config) (previous completed : Nat) :
    previous + c.intervalNs ≤ nextDeadline c previous completed := by
  unfold nextDeadline
  split <;> omega

inductive Action where
  | arrival (packet : Packet)
  | tick (now completed : Nat) (succeeded : Bool)
  deriving Repr

/-- Arrivals never trigger a send directly. A due tick attempts exactly one record,
including when the queue is empty. The 64-bit sequence guard describes the source's
packing limit; the model makes no claim about operation after sequence exhaustion. -/
inductive Step (c : Config) : State → Action → State → Prop where
  | arrive (before : State) (packet : Packet) :
      Step c before (.arrival packet) { before with queue := enqueue c before.queue packet }
  | tick (before : State) (now completed : Nat) (succeeded : Bool)
      (due : before.deadlineNs ≤ now) (clock : now ≤ completed)
      (encodable : before.sequence + 1 < 2 ^ 64) :
      Step c before (.tick now completed succeeded)
        { queue := before.queue.tail
          attempts := ⟨now, paddedBytes c (payload before.queue), succeeded⟩ :: before.attempts
          deadlineNs := nextDeadline c before.deadlineNs completed
          sequence := before.sequence + 1 }

def system (c : Config) : Cslib.LTS State Action := ⟨Step c⟩

def Safe (c : Config) (state : State) : Prop :=
  QueueValid c state.queue ∧ ∀ attempt ∈ state.attempts, attempt.bytes = c.recordBytes

lemma step_preserves_size_and_capacity {c : Config} (valid : c.Valid) :
    (system c).TrInv (Safe c) := by
  intro before action after step checked
  cases step with
  | arrive packet =>
    exact ⟨enqueue_preserves_queue checked.1 packet, checked.2⟩
  | tick now completed succeeded due clock encodable =>
    refine ⟨tail_preserves_queue checked.1, ?_⟩
    intro attempt member
    rcases List.mem_cons.mp member with newest | prior
    · subst attempt
      exact padding_gives_fixed_length valid (payload_fits checked.1)
    · exact checked.2 attempt prior

/-- CSLib lifts the two local queue/send cases to every finite execution. Arbitrary
arrival sizes, full queues and failed sends preserve capacity and fixed record size. -/
theorem all_executions_have_bounded_queues_and_fixed_records {c : Config}
    (valid : c.Valid) {firstDeadline : Nat} {actions : List Action} {finish : State}
    (run : (system c).MTr (initial firstDeadline) actions finish) : Safe c finish := by
  exact Cslib.LTS.mtrInv_of_trInv (step_preserves_size_and_capacity valid)
    _ _ _ run (by simp [Safe, QueueValid, initial])

/-- Under the same send times and link outcomes, observing record sizes adds no
information about queued payload sizes. The model does not assume actual OS timing
or link failures are independent of offered traffic. That stronger claim needs evidence. -/
theorem equal_schedule_gives_equal_size_observations {c : Config}
    {left right : State} (hl : Safe c left) (hr : Safe c right)
    (schedule : left.attempts.map (fun a => (a.atNs, a.succeeded)) =
      right.attempts.map (fun a => (a.atNs, a.succeeded))) :
    left.attempts.map (fun a => (a.atNs, a.bytes, a.succeeded)) =
      right.attempts.map (fun a => (a.atNs, a.bytes, a.succeeded)) := by
  have normalize (state : State) (safe : Safe c state) :
      state.attempts.map (fun a => (a.atNs, a.bytes, a.succeeded)) =
        (state.attempts.map (fun a => (a.atNs, a.succeeded))).map
          (fun pair => (pair.1, c.recordBytes, pair.2)) := by
    rw [List.map_map]
    apply List.map_congr_left
    intro a member
    simp only [Function.comp_apply, safe.2 a member]
  rw [normalize left hl, normalize right hr, schedule]

end TDN.CoverTraffic
