# Notary key rotation

Machines pin the notary's key. Pinning is the point — and it is also the trap: a pinned
key that can never change is a key whose loss, or theft, ends the service. This document
is the written procedure for changing the countersigning key without breaking a single
pinned machine, and the exact semantics that make it safe.

## The two ideas

**1. A threshold counts parties, not keys.**

A subscription's threshold exists to prove that more than one *party* agreed to the
catalog — publisher and notary. During rotation the notary briefly has two keys. If each
key counted separately, a machine pinning the rotation pair at threshold 2 would accept a
catalog signed by the two notary keys alone: one party, counted twice, and the stolen-key
protection silently gone.

So `skillctl` groups a rotation pair into one *party* (`parties` in the subscription
file), and the threshold counts distinct parties. Publisher + either notary key = 2.
Both notary keys alone = 1, refused. Subscriptions without parties behave exactly as
before — every key is its own party.

**2. Trust extends along a chain, never restarts.**

The notary serves `GET /v1/keys`: a DSSE envelope announcing its current keys, signed by
*all* of them. A machine that pins any one current key can verify the announcement and
learn the incoming key over its existing trust — no second trust-on-first-use, no hoping
about TLS. A stranger who pins nothing learns nothing they can use.

## The ceremony

1. **Generate the incoming key.** Do not retire anything yet.
2. **Open the overlap window:** run the notary with both keys, outgoing first
   (`notary.NewFrom(storage, directory, outgoing, incoming)`; the hosted deployment
   concatenates both private-key PEMs in its key parameter). From this moment every
   catalog is countersigned by both keys, and `/v1/keys` announces both.
3. **Machines catch up on their own.** `skillctl sync` fetches `/v1/keys` in passing,
   verifies it against the pins it already holds, and adds the incoming key to the same
   party as the outgoing one. Add-only: an announcement can never shrink a machine's
   pins. `skillctl refresh` does the same loudly, on demand.
4. **Close the window:** once the fleet has synced at least once, run the notary with
   only the incoming key. `/notary.pub` and new subscribe instructions now hand out the
   new key.
5. **Retire the outgoing pin** (optional, operator's call):
   `skillctl trust --remove <label>`. Machines that skip this lose nothing but tidiness.

## Failure semantics — explicit, because they are the design

- **A machine that never synced during the window** fails **closed** after step 4: the
  catalog carries only the incoming key's signature, which that machine does not pin, and
  sync reports exactly which requirement went unmet. It resubscribes with the current
  `notary.pub`, or an operator pins the new key by hand. Nothing is silently accepted.
- **Offline machines** are untouched: sync in `--offline` mode never fetches
  announcements, and existing pins keep verifying whatever was already fetched.
- **A server that predates `/v1/keys`** answers 404; sync treats a failed announcement as
  a non-event and verifies against existing pins.

## What rotation honestly cannot do

Whoever holds a current key *is* the notary as far as the protocol can tell, so a stolen
current key can announce a successor the thief controls. Two things bound that damage:

- The announcement only ever **adds** keys on machines. The legitimate keys stay pinned,
  so the thief cannot lock the operator out of the fleet's trust.
- A notary key — stolen, rotated, either or both — **publishes nothing alone.** The
  threshold still requires the publisher's party, which the thief does not hold.

That is why the overlap window should be short, and why key compromise is handled by
rotating *away* from the stolen key immediately: every machine that syncs during the
window picks up the clean key, and closing the window strands the stolen one.

Rotating the *publisher's* key is the same mechanism from the other side: the
organisation updates its registered publisher keys with the notary, publishes one catalog
signed by both old and new publisher keys, and consumers' `parties` group them the same
way. The announcement endpoint is the notary's; publishers rotate through the catalogs
themselves.
