# Scanning before signing

A signature answers "who published these bytes, and have they changed". It has never
answered "what do they do", and nothing in this project pretends otherwise. `skillctl
scan` narrows that gap by running [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector)
(Apache-2.0) over a skill and reporting what it finds.

```bash
uv tool install git+https://github.com/NVIDIA/skillspector.git
skillctl scan ./plugins/deploy-runbook
```

`skillctl marketplace sign` runs the same scan over every plugin it is about to sign and
refuses the ones the scanner says not to install. Signing is the moment a publisher takes
responsibility for bytes; the gate removes the case where nobody looked at all.

## What is free, what costs

**Static analysis is local and unmetered.** It reads files on your machine, sends nothing
anywhere, and is deterministic — the same bytes give the same verdict. There is no version
of this product where the basic check is the paid tier.

**The semantic pass is opt-in**, because it transmits file contents to a model provider.
`--scan-llm` uses whichever provider you configured (`SKILLSPECTOR_PROVIDER`); the hosted
service can run it for you, and that is the metered thing, because those tokens cost real
money. Own key, own bill, no limit.

## What the semantic pass costs

On Bedrock, two environment variables are the whole setup:

```bash
export SKILLSPECTOR_PROVIDER=bedrock
export SKILLSPECTOR_MODEL=us.amazon.nova-lite-v1:0
skillctl scan ./plugins/deploy-runbook --llm
```

Every scan prints the tokens it spent, so the bill is knowable before it arrives. Measured
on one real skill (`systematic-debugging`, 14 files), against AWS on-demand list prices in
`us-east-1` fetched from the Price List API in August 2026:

| Model | tokens in / out | per skill | per 1000 skills |
|---|---|---|---|
| `us.amazon.nova-micro-v1:0` | 10 189 / 632 | $0.00047 | **$0.47** |
| `us.amazon.nova-lite-v1:0` | 10 189 / 717 | $0.00077 | **$0.77** |
| `us.amazon.nova-2-lite-v1:0` | 13 392 / 1 131 | $0.0080 | $8.00 |

Nova Lite is the sensible default: a tenth the price of Nova 2 Lite on the same skill. Your
own numbers will differ with skill size — that is why the tool prints them.

`skillctl` supplies the scanner with token budgets for these models, because it ships with
none for Nova and derives them from the context window instead. Nova has a very large
context and a small output cap, so the derived budget is one Nova refuses, and **every
semantic call then fails while the scan still succeeds** — the failures come back as
"referenced artifact was not completely inspected" findings, and the skill scores worse for
a misconfiguration on your side. Uncorrected, that scored this same skill 90 instead of 66.
Setting `SKILLSPECTOR_MODEL_REGISTRY` yourself takes the decision back.

## Read the findings; do not obey the score

A static scanner matches patterns, and a skill that *teaches* about a risk contains the
same strings as a skill that *is* one. Measured on this project's own curated catalog, the
scanner refused four of eleven skills — and the most instructive refusal was a security
skill flagged for:

- `169.254.169.254`, the cloud metadata address, which appears because the skill explains
  how to block SSRF to it;
- `.env`, because it lists the files a `.gitignore` must exclude;
- the substring `Model; disable security`, spanning a table cell boundary in its STRIDE
  section.

Three of those four refusals were teaching material and helper scripts doing exactly what
they say. That is not a defect in the scanner — pattern matching cannot read intent — but
it is why the gate is a prompt to look, not a verdict to obey:

```bash
skillctl marketplace sign . --sign-anyway
```

Use it once you have read the findings and decided they are acceptable, and say why in the
commit message. A gate that cannot be overridden gets removed; a gate that is overridden
silently was never a gate.

## What this still does not tell you

The scanner never executes the skill. It cannot see what a script does at run time, what a
URL it fetches will return, or what instructions a document will carry after its next
update. Detection, not enforcement — the same honesty the rest of this project keeps.
