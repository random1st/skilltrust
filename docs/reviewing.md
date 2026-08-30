# Running a review panel against this repository

Two runs of the adversarial review died before producing anything, and the second looked
like a clean result — zero findings — which is the most dangerous way for a review to fail.
This is what went wrong, so the next person does not spend a day rediscovering it.

## The panel was not hanging; the account was throttled

Nine agents, eight of them reported by the runner as "stalled on all 6 attempts (no
progress for 180000ms each)". The agent transcripts say otherwise. Timestamps from the
second run:

```
gap starts  gap ends    seconds  agents
11:04:18    11:23:35       1157  eight, simultaneously
11:23:35    11:41:39       1085  eight, simultaneously
11:41:39    11:59:20       1061  eight, simultaneously
11:59:20    12:15:24        964  eight, simultaneously
12:15:24    12:31:10        946  eight, simultaneously
12:31:10    12:48:43       1053  eight, simultaneously
```

Every agent in a batch froze on the same second and resumed on the same second. Agents do
not hang in unison, and their last recorded event was an ordinary tool result followed by
an interruption — they were working, and something outside them stopped answering. That is
the account being throttled as a whole.

The first run's failure — twelve of fourteen agents on "Login expired" — is the same
family, one layer up.

## The retries made it worse

The runner treats no-progress-for-180-seconds as a stalled agent and retries. Under a
throttle that means killing a request that was queued and issuing another one, six times
per agent, against an account that is already refusing. Raising the timeout would not have
helped. The retries were the amplifier.

## What to do instead

**Fewer and larger, not many and small.** Two attackers at once, verifiers one at a time.
A review that takes an hour and returns findings beats one that returns nothing in two.

**Never read an empty panel as a clean result.** The second run reported zero findings and
`trustworthy: true`, because nothing had been raised and therefore nothing was
unadjudicated. The script now counts the attackers that answered and says `PANEL DEAD - no
lens answered. This says nothing about the code.` A run where every lens died is the least
informative result there is, and it used to be the one that looked best.

**A dead verifier is not a refutation.** The first version filed findings whose verifier had
died under "refuted", which reads as "we checked and it was wrong". Three of those were
real defects, found later by hand. Unjudged findings now have their own bucket.

## What the panel found anyway

One surviving agent named a file nobody had opened — the session-start hook, which rendered
an adopted plugin without the reason it was adopted for. One agent out of nine paid for the
run. That is the argument for fixing the throttling rather than abandoning the panel.
