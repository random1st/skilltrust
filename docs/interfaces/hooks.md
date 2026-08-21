# Validation hooks

Hook definitions come from signed trust policy, never from the contribution being checked. A hook
is an argv tuple, timeout, required flag, and either no network or an explicit hostname allowlist.
Shell strings are not supported.

The control plane does not claim that a normal subprocess is sandboxed. An external adapter must
prove read-only/temporary filesystem isolation, secret isolation, and network denial/allowlist
enforcement. No adapter, exception, timeout, malformed result, excessive output, or missing proof is
`UNKNOWN`; a required hook then denies notarization.

Hook evidence stored in a `PASS` result is content-addressed and bound to the exact artifact digest,
validator version, start/end time, and policy digest. stdout is diagnostic data, not authority.

