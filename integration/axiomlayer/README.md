# AxiomLayer ripgrep integration lane

`axiomlayer/ripgrep` is a GitHub fork of `BurntSushi/ripgrep`. Upstream remains
the source of the ripgrep project and is never modified by this layer. The fork
adds only the fleet's promotion evidence around an exact upstream revision.

The current candidate is ripgrep 15.2.0 at
`e89fff89ac9af12e8d4ce9d5fd07beb408ca730f`, exactly matching the source and
artifact pins in `axiomlayer/dotfiles` PR #49 at
`d7a9c4afc1083c17c06a2f82beb63a5d6292dca0`. The manifest records all six
release archive SHA-256 values and all six extracted `rg` binary SHA-256 values.
Those values are checked once as a complete set and again on the matching
native host before the build/test-only promotion gate can pass.

## Evidence boundary

- Linux x86_64/ARM64 and macOS x86_64/ARM64 materialize the exact Git commit,
  then build and test it with Nix 2.35.2 and the digest-locked Nixpkgs revision
  already selected by Dotfiles #49.
- Windows x86_64/ARM64 materialize the same commit, then build and test it with
  Cargo `--locked` and upstream's minimum Rust 1.85.0 toolchain. Native Nix is
  explicitly unsupported on Windows; it is not emulated or silently skipped.
- Every native job downloads the matching upstream 15.2.0 release asset,
  verifies archive size and SHA-256, safely extracts it, verifies the binary
  SHA-256, executes `rg --version`, and emits a local receipt bound to the
  candidate and target.
- WSL x86_64/ARM64 cannot be represented by a GitHub-hosted runner. Their
  explicit proof remains a downstream physical Ocelot/Siberian acceptance
  receipt using the corresponding Linux artifact.

The integration workflow grants its automatic token only `contents: read`.
Every checkout is clean, fetches the promoted history, and sets
`persist-credentials: false`; no configured or fabricated credential is used.
Every job is bound to the exact lowercase fork identity and to a same-repository
default-branch pull-request merge ref, a protected default-branch push, or a
protected daily or manual default-branch run of this exact workflow. Every
checkout is explicitly bound to the event SHA. Fork-origin pull requests are
refused, and the native matrix cannot start until the integrity contract passes.
The daily hosted canary runs at 06:17 UTC. The workflow declares no environment
and publishes nothing.

Hosted Nix jobs verify the official 2.35.2 launcher SHA-256 and its embedded
platform tarball digest. The shell starts from an absolute `/usr/bin/env -i`
boundary, the installer receives a fixed system path and private temporary root,
and Nix evaluation runs through a second empty environment with an absolute Nix
binary path. The manifest also binds the complete `default.nix` bytes.

The inherited upstream `ci.yml` and `release.yml` are not executable in the
fork. Those workflows and the complete inherited `ci/` support tree are
quarantined under `integration/axiomlayer/upstream-workflows` as byte-identical,
path-preserving copies from upstream commit
`3fce3b5bb0236da2df6d99672afb8a719642eca7`. The manifest records each source
path, archive path, Git mode, and SHA-256. The verifier compares the complete
baseline Git inventories and every archived byte, refuses missing, extra,
renamed, or linked archive entries, and requires the AxiomLayer integration to
be the only file left in the executable workflow directory.

All external Actions in the sole executable workflow use reviewed full
40-character commits. The verifier refuses floating tags, branches, and
unreviewed full-SHA Actions. Floating references in the quarantined files are
retained only as byte-exact upstream provenance and cannot execute as Actions.

## Local checks

```sh
python3 integration/axiomlayer/verify.py validate
python3 integration/axiomlayer/verify.py verify-source
python3 integration/axiomlayer/verify.py verify-workflows
python3 -m unittest -v integration/axiomlayer/test_verify.py
python3 integration/axiomlayer/verify.py verify-all-assets \
  --directory /tmp/axiomlayer-ripgrep-assets
```

The Nix derivation accepts a detached worktree containing the promoted source:

```sh
python3 integration/axiomlayer/verify.py materialize-source \
  --destination /tmp/ripgrep-15.2.0
nix-build integration/axiomlayer/default.nix \
  --arg src /tmp/ripgrep-15.2.0 \
  --argstr system "$(nix eval --impure --raw --expr builtins.currentSystem)" \
  --no-out-link
```

This lane is evidence for promotion; it is not promotion authority and does not
upload, mirror, tag, release, attest, or sign artifacts.
