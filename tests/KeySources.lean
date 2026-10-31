import TDN.Targets.MACsecFallback

open TDN.KeySources

/-- Renewed EAP participants can coexist without becoming fallback PSKs. -/
example : OnlyAuthenticatedSources [⟨1, .authenticatedExchange⟩, ⟨2, .authenticatedExchange⟩] := by
  unfold OnlyAuthenticatedSources
  decide

/-- Configuring both pre-shared fields makes pre-shared creation possible. The
general no-fallback theorem cannot be applied to that changed configuration. -/
example : Step ⟨true, true⟩ [] (.preShared 3) [⟨3, .preSharedConfiguration⟩] :=
  .preShared [] 3 rfl

example : ¬ OnlyAuthenticatedSources [⟨3, .preSharedConfiguration⟩] := by
  unfold OnlyAuthenticatedSources
  decide

/-- A lone name cannot satisfy hostap's complete CAK-and-CKN guard. -/
example : (Config.mk false true).preSharedEnabled = false := by decide
