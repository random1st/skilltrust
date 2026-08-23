# Running the gate in CI

The gate is one command and one exit code:

```bash
skillctl catalog verify . --key catalog.pub
```

`0` the signed index still names the exact bytes in the repository, `1` it does not, `3` it
could not be checked. Everything below is that command with a different amount of ceremony
around it, so a CI this page does not mention is not a CI that cannot run it.

Two rules apply everywhere and are worth stating once:

**Commit the public key.** The check is only as good as the key it checks against, and a key
supplied by the same system that can change the pipeline definition checks nothing. `catalog.pub`
belongs in the repository, next to the index it verifies.

**Verify in CI; sign somewhere else if you can.** A signing key in a CI secret means whoever
can change a pipeline can publish a signed marketplace — the pipeline definition usually lives
in the repository the pipeline guards. If you sign in CI anyway, require more than one
signature so that reaching the pipeline is not enough on its own; see
[Requiring two signatures](#requiring-two-signatures).

## GitHub Actions

```yaml
- uses: random1st/skilltrust@v1
  with:
    command: verify
    public-key: catalog.pub
```

The action builds the binary from its own checkout rather than downloading it, so the check
that guards a repository is not fetched over the network at the moment it runs.

## Azure DevOps

Azure Pipelines has no equivalent of a composite action that carries its own source, so the
step is explicit. That is not a downgrade: it is the same two commands the action runs.

```yaml
trigger:
  branches: { include: [main] }
  paths:
    include: [plugins/*, .claude-plugin/*, catalog.dsse.json]

pool:
  vmImage: ubuntu-latest

steps:
  - task: GoTool@0
    inputs:
      version: '1.26'

  # Pin the tool by tag. Building from `main` would mean the gate changes without anyone
  # deciding that it should, which is the same failure the gate exists to catch, one level up.
  - script: |
      set -euo pipefail
      git clone --depth 1 --branch v0.1.0 https://github.com/random1st/skilltrust "$(Agent.TempDirectory)/skilltrust"
      cd "$(Agent.TempDirectory)/skilltrust/client"
      go build -trimpath -o "$(Agent.TempDirectory)/skillctl" ./cmd/skillctl
    displayName: Build skillctl

  - script: |
      set -euo pipefail
      "$(Agent.TempDirectory)/skillctl" catalog verify "$(Build.SourcesDirectory)" \
        --key "$(Build.SourcesDirectory)/catalog.pub"
    displayName: The signature still describes this repository
```

A private SkillTrust repository needs credentials for that clone. Use a service connection or
a PAT in a variable group rather than embedding one in the YAML:

```yaml
  - script: |
      git clone --depth 1 --branch v0.1.0 \
        "https://$(SKILLTRUST_PAT)@github.com/random1st/skilltrust" "$(Agent.TempDirectory)/skilltrust"
    env:
      SKILLTRUST_PAT: $(skilltrustPat)
```

**Branch policy is what makes it a gate.** A failing pipeline blocks nothing by itself. Add
the build as a *required* check under Repos → Branches → main → Branch policies → Build
validation, or the red run is a notification and the merge happens anyway.

To sign from a pipeline, put the private key in a variable group backed by Azure Key Vault,
mark it secret, and write it to a file the step deletes:

```yaml
  - script: |
      set -euo pipefail
      umask 077
      printf '%s' "$SIGNING_KEY" > "$(Agent.TempDirectory)/signing.key"
      trap 'rm -f "$(Agent.TempDirectory)/signing.key"' EXIT
      "$(Agent.TempDirectory)/skillctl" marketplace sign "$(Build.SourcesDirectory)" \
        --key "$(Agent.TempDirectory)/signing.key"
    env:
      SIGNING_KEY: $(marketplaceSigningKey)
    displayName: Sign the marketplace
```

`umask 077` before writing and `trap … EXIT` after are not decoration. A self-hosted agent
keeps its temporary directory between jobs, so a key written world-readable and left behind is
a key the next pipeline on that agent can read.

## GitLab CI

```yaml
verify-marketplace:
  image: golang:1.26
  rules:
    - changes: [plugins/**/*, .claude-plugin/**/*, catalog.dsse.json]
  script:
    - git clone --depth 1 --branch v0.1.0 https://github.com/random1st/skilltrust /tmp/skilltrust
    # Build from inside the clone: go resolves the module from the working directory,
    # so a path into somebody else's checkout fails with "go.mod file not found".
    - (cd /tmp/skilltrust/client && go build -trimpath -o /tmp/skillctl ./cmd/skillctl)
    - /tmp/skillctl catalog verify . --key catalog.pub
```

Make it a required job for the merge request, not merely a job that runs.

## Jenkins, Buildkite, Bamboo, anything else

```groovy
sh 'cd skilltrust/client && go build -trimpath -o "${WORKSPACE}/skillctl" ./cmd/skillctl'
sh './skillctl catalog verify . --key catalog.pub'
```

The exit code is the contract. `3` means the check could not run — a missing key, an
unreadable index — and must not be treated as a pass; if your CI collapses non-zero codes into
"failed", that is the correct behaviour here.

## Requiring two signatures

A threshold is set by the machines that consume the marketplace, never declared by the
marketplace itself: a publisher whose key was stolen would declare a threshold of one.

```bash
skillctl subscribe git@github.com:acme/marketplace.git \
  --key author.pub --key reviewer.pub --threshold 2
```

The author signs, and a second person countersigns after reading what they are agreeing to:

```bash
skillctl marketplace countersign . --expect-sequence 7
```

`--expect-sequence` matters more than it looks. Without it a republish between review and
countersignature carries the reviewer's agreement onto an index they never saw.

An author cannot reach the threshold alone: signing twice with one key is refused, and
duplicate signatures from one key count once. Republishing drops the index back to one
signature and machines refuse it until it is countersigned again — which is the point, and is
also the cost. A team that finds that too slow should say so before deploying a threshold
rather than after.
