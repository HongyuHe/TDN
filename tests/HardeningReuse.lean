import TDN.Network.Hardening

/-!
Independent startup and resolver fixtures reuse the same generic proof.
No MSC device, policy constant, or snapshot is imported. The two DNS branches
remain distinct, and unknown or remotely controlled startup cannot pass.
-/
open TDN.Network.Hardening

private def localProgram : List StartupAction := [.loopbackUp, .startSwitch [], .idle]

example (effects : List StartupEffect) (execution : StartupTrace localProgram effects) :
    ∀ effect ∈ effects, effect = .local :=
  local_startup_has_no_network_configuration (by decide) execution

example : localStartup [.loopbackUp, .unknown "tftp configuration", .idle] = false := by decide
example : localStartup [.startSwitch ["tcp:192.0.2.1:6640"]] = false := by decide
example : localStartup [.remoteConfiguration "https://192.0.2.1/boot"] = false := by decide

example : DNSPolicy.disabled.accepts ⟨[], ["files"]⟩ = true := by decide
example : DNSPolicy.disabled.accepts ⟨[], ["files", "dns"]⟩ = false := by decide
example : (DNSPolicy.specified [3221225985]).accepts
    ⟨[3221225985], ["files", "dns"]⟩ = true := by decide
example : (DNSPolicy.specified [3221225985]).accepts
    ⟨[3221225985, 3221225986], ["files", "dns"]⟩ = false := by decide

example : StartupTrace [.unknown "network-bootstrap"] [.networkConfiguration "192.0.2.1"] :=
  .step trivial .done
