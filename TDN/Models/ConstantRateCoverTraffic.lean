import Cslib.Foundations.Semantics.LTS.Basic
import Mathlib.Data.List.Basic
import Lean.Elab.Tactic.Omega

namespace TDN.CoverTraffic

structure ScheduleConfig where
  recordBytes : Nat
  headerBytes : Nat
  queueLimit : Nat
  intervalNs : Nat
  deriving DecidableEq, Repr

def ScheduleConfig.Valid (c : ScheduleConfig) : Prop :=
  c.headerBytes ≤ c.recordBytes ∧ 0 < c.queueLimit ∧ 0 < c.intervalNs

instance (c : ScheduleConfig) : Decidable c.Valid := by
  unfold ScheduleConfig.Valid
  infer_instance

abbrev Packet := List UInt8

def QueueValid (c : ScheduleConfig) (queue : List Packet) : Prop :=
  queue.length ≤ c.queueLimit ∧
  ∀ packet ∈ queue, packet.length ≤ c.recordBytes - c.headerBytes

def enqueue (c : ScheduleConfig) (queue : List Packet) (packet : Packet) : List Packet :=
  if packet ≠ [] ∧ packet.length ≤ c.recordBytes - c.headerBytes ∧
      queue.length < c.queueLimit then queue ++ [packet] else queue

def payload (queue : List Packet) : Packet :=
  match queue with
  | [] => []
  | first :: _ => first

def paddedBytes (c : ScheduleConfig) (packet : Packet) : Nat :=
  c.headerBytes + packet.length + (c.recordBytes - c.headerBytes - packet.length)

lemma padding_gives_fixed_length {c : ScheduleConfig} (valid : c.Valid)
    {packet : Packet} (fits : packet.length ≤ c.recordBytes - c.headerBytes) :
    paddedBytes c packet = c.recordBytes := by
  unfold paddedBytes
  have := valid.1
  omega

lemma enqueue_preserves_queue {c : ScheduleConfig} {queue : List Packet}
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

lemma tail_preserves_queue {c : ScheduleConfig} {queue : List Packet}
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

lemma payload_fits {c : ScheduleConfig} {queue : List Packet}
    (valid : QueueValid c queue) :
    (payload queue).length ≤ c.recordBytes - c.headerBytes := by
  cases queue with
  | nil => simp [payload]
  | cons first rest => exact valid.2 first (List.mem_cons_self ..)

structure Attempt where
  atNs : Nat
  bytes : Nat
  succeeded : Bool
  deriving DecidableEq, Repr

structure SchedulerState where
  queue : List Packet
  attempts : List Attempt
  deadlineNs : Nat
  sequence : Nat
  deriving Repr

def initial (firstDeadline : Nat) : SchedulerState := ⟨[], [], firstDeadline, 0⟩

def nextDeadline (c : ScheduleConfig) (previous completed : Nat) : Nat :=
  if previous + c.intervalNs < completed then completed + c.intervalNs
  else previous + c.intervalNs

lemma deadline_advances (c : ScheduleConfig) (previous completed : Nat) :
    previous + c.intervalNs ≤ nextDeadline c previous completed := by
  unfold nextDeadline
  split <;> omega

inductive SchedulerAction where
  | arrival (packet : Packet)
  | tick (now completed : Nat) (succeeded : Bool)
  deriving Repr

inductive SchedulerStep (c : ScheduleConfig) : SchedulerState → SchedulerAction → SchedulerState → Prop where
  | arrive (before : SchedulerState) (packet : Packet) :
      SchedulerStep c before (.arrival packet) { before with queue := enqueue c before.queue packet }
  | tick (before : SchedulerState) (now completed : Nat) (succeeded : Bool)
      (due : before.deadlineNs ≤ now) (clock : now ≤ completed)
      (encodable : before.sequence + 1 < 2 ^ 64) :
      SchedulerStep c before (.tick now completed succeeded)
        { queue := before.queue.tail
          attempts := ⟨now, paddedBytes c (payload before.queue), succeeded⟩ :: before.attempts
          deadlineNs := nextDeadline c before.deadlineNs completed
          sequence := before.sequence + 1 }

def system (c : ScheduleConfig) : Cslib.LTS SchedulerState SchedulerAction := ⟨SchedulerStep c⟩

def Safe (c : ScheduleConfig) (state : SchedulerState) : Prop :=
  QueueValid c state.queue ∧ ∀ attempt ∈ state.attempts, attempt.bytes = c.recordBytes

lemma step_preserves_size_and_capacity {c : ScheduleConfig} (valid : c.Valid) :
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

theorem all_traces_have_bounded_queues_and_fixed_records {c : ScheduleConfig}
    (valid : c.Valid) {firstDeadline : Nat} {actions : List SchedulerAction} {finish : SchedulerState}
    (run : (system c).MTr (initial firstDeadline) actions finish) : Safe c finish := by
  exact Cslib.LTS.mtrInv_of_trInv (step_preserves_size_and_capacity valid)
    _ _ _ run (by simp [Safe, QueueValid, initial])

theorem equal_schedule_gives_equal_size_observations {c : ScheduleConfig}
    {left right : SchedulerState} (hl : Safe c left) (hr : Safe c right)
    (schedule : left.attempts.map (fun a => (a.atNs, a.succeeded)) =
      right.attempts.map (fun a => (a.atNs, a.succeeded))) :
    left.attempts.map (fun a => (a.atNs, a.bytes, a.succeeded)) =
      right.attempts.map (fun a => (a.atNs, a.bytes, a.succeeded)) := by
  have normalize (state : SchedulerState) (safe : Safe c state) :
      state.attempts.map (fun a => (a.atNs, a.bytes, a.succeeded)) =
        (state.attempts.map (fun a => (a.atNs, a.succeeded))).map
          (fun pair => (pair.1, c.recordBytes, pair.2)) := by
    rw [List.map_map]
    apply List.map_congr_left
    intro a member
    simp only [Function.comp_apply, safe.2 a member]
  rw [normalize left hl, normalize right hr, schedule]

end TDN.CoverTraffic
