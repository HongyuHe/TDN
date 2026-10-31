import Std.Time.DateTime.PlainDateTime

namespace TDN.CalendarTime

/-- Add calendar months to a nonnegative Unix timestamp in UTC. The standard
Gregorian library clips an absent destination day to the month's final day.
The result preserves time of day. These numbers are seconds, never event indices. -/
def addMonthsClip (utcSeconds months : Nat) : Nat :=
  let date := Std.Time.PlainDateTime.ofWallTime
    (Std.Time.WallTime.ofSeconds (.ofNat utcSeconds))
  ((date.addMonthsClip (.ofNat months)).toWallTime.toSeconds).val.toNat

/-- The selected annual boundary uses twelve calendar months. -/
def oneYearAfter (utcSeconds : Nat) : Nat := addMonthsClip utcSeconds 12

/-- Six calendar months from notification, independently of annual renewal. -/
def sixMonthsAfter (utcSeconds : Nat) : Nat := addMonthsClip utcSeconds 6

end TDN.CalendarTime
