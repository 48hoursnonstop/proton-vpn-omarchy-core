# 0.9.10 release validation — 2026-10-09

Review of the installed 0.9.9 release reproduced two cancellation gaps in
isolated backend fixtures. No live tunnel was created on the protected network.

- A manual cancellation/disconnection while the startup agent was waiting for
  the keyring was forgotten when account restoration later completed. The
  operation baseline now covers the complete startup sequence, including that
  wait. Explicitly disabling and re-enabling auto-connect starts a new sequence.
- Reconnection after system suspend retried cancellation and permanent errors,
  and did not stop when a manual action occurred between retries. Resume now
  observes operation changes during backoff and before connecting; only transient
  connection errors are retried. An earlier active session still reconnects
  independently of the auto-connect preference, preserving existing behavior.
- Startup and resume share the operation interruption predicate. Cancellation
  of a security-key login does not permanently suppress a later VPN connection.

## Verification

The new keyring-wait and resume regressions failed against the previous logic.
The complete workspace suite now passes: 158 tests, zero failures, eight
explicitly opt-in tests ignored. Positive regressions verify transient resume
retry, later successful sign-in and explicit auto-connect re-enabling.

The release workflow also repeats the workspace suite and disposable GNOME
Keyring checks with passwordless and encrypted collections. Dependency versions
remain locked; only the three workspace package versions change in Cargo.lock.

Read-only checks on the installed 0.9.9 package confirmed all 41 package files
unchanged, no local service override, and healthy agent/split services. After
the machine's subsequent boot, IPC still reports an authenticated account,
nine profiles, five recents and unchanged startup/locale preferences.

## Compatibility

No Secret Service implementation, namespace, session envelope, profile schema
or IPC wire format changed. The `Proton VPN for Omarchy` namespace and `pvom1:` /
`pvom-index1:` envelopes remain compatible with 0.9.6-rc1. The frontend update
pins the matching signed and attested 0.9.10-1 package without changing the UI.
