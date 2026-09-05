# SkillTrust, for an agent setting it up

What this is, what it does not claim, and the order things have to happen in.

## What it proves

A skill directory has a canonical digest. A publisher signs an index of those digests with a
key that stays on their machine. A machine that follows that index pins the public half in
advance and refuses anything that key did not sign.

That proves **who published these bytes, and that they have not changed since**. It does not
prove the skill is safe, correct, or does what its description says. Nothing here inspects
what a skill does. Reporting a verified skill as "safe" is the one wrong sentence to say
about this tool.

## The normal hosted path

On hosted Axela, the normal consumer setup is `skilltrust_connect`. It wraps the real
`skillctl connect` flow: creates or reuses the machine key, returns the public approval URL,
stores the reporting credential locally only after approval, bootstraps the catalog
subscriptions, installs the managed session hooks it can see, and runs the first check.

Approval still happens in a browser already signed into Axela. The MCP tool should usually
return immediately with the approval URL so the browser step stays explicit. If the tool says
`pending`, approval or the first acknowledgement has not finished yet; rerun it after the
browser step. Do not say this machine is fully connected or protected until it says
`connected`, because before that Axela has not yet acknowledged the exact first check.

## The order, and why it is not arbitrary

Every step succeeds out of order. That is why the order is written down.
If you are using hosted Axela, that order is normally wrapped inside `skilltrust_connect`.
The manual steps below are for local or self-hosted setups, and for understanding what the
hosted flow is doing on the machine.

**Key before anything.** `skilltrust_init` creates the signing key. Its public half is what a
publisher registers and an administrator pins. Running init twice is safe; it will not
replace an existing key, because replacing it would unpin this machine everywhere it is
trusted, silently.

**Pin before subscribe.** A pinned key has to come from somewhere already trusted — a file
handed over, a key read off a console someone signed into. A key learned from the catalog it
is meant to verify proves nothing: whoever can serve the catalog can serve the key.

**Threshold with the pins.** Pinning two keys and leaving the threshold at 1 means either key
alone is accepted. Everything verifies. Nothing ever reports it. The second key was pinned so
that a single stolen key would not be enough, and a threshold of 1 gives exactly that back.
When there are two keys, the number is 2.

**Check before sync.** `skilltrust_check` writes nothing. A difference is not necessarily an
attack — it is often someone's uncommitted work in an installed skill. `skilltrust_sync`
restores the signed version and keeps the copy it replaced, but a person who is not told
where their edit went will conclude the tool ate it.

**Hook last, and actually applied.** Checking on demand and checking at the start of every
session are different claims. Printing the hook configuration is not installing it.

## The two keys, when a notary is involved

Self-hosted, there is one signature: the publisher's. With a notary, there are two — the
publisher signs, the notary countersigns, and a machine pins both with a threshold of 2. A
stolen publisher key then publishes nothing, because the notary refuses to countersign for a
repository it does not match; and a compromised notary publishes nothing either, because it
has no publisher key to forge.

This only holds if the consumer set the threshold. The publisher cannot set it for them: a
publisher whose key was stolen would declare a threshold of 1.

## What an agent cannot do

Browser approval still happens in a browser, behind an existing Axela sign-in. An agent can
start or resume the connection and hand over the approval URL; it cannot manufacture that
consent.

Publisher registration is a separate browser flow. Registering an organisation and binding a
publishing repository happen behind a sign-in and return credentials shown once. There is no
API to call and no credential to hold in the conversation. Hand the human the public key and
the console URL, and tell them the normal non-empty publish path is GitHub Actions OIDC from
that registered repository. The publish token is for empty or revocation-only catalogs, or
for recovery; if they need it, ask for it in the environment rather than in the conversation.

## Where things live

    ~/.skilltrust/signer.key        the private half; never read, never copied, never in CI
    ~/.skilltrust/signer.pub        the public half; this is what gets registered and pinned
    ~/.skilltrust/trusted-keys.json the pinned set, by label
    ~/.skilltrust/catalogs.json     what this machine follows, with keys and thresholds
    ~/.skilltrust/catalog.json      a publisher's own index and its revocations

`SKILLTRUST_HOME` moves all of it.

## The honest limit

On a laptop, anything that can edit a skill can edit the checker. This is detection, not
enforcement: it makes a change visible and attributable, and it does not make a change
impossible. The managed-settings path (`skillctl policy`) is what makes it binding on a
fleet, and it needs an administrator, not an agent.
