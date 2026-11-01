# Release and rules signing

Kunato verifies two kinds of detached minisign signatures with public keys
embedded in the binary:

| Artifact | Signature | Verified by |
| --- | --- | --- |
| `dist/rules.yaml` | `dist/rules.yaml.minisig` | `rules_update` (daemon and `kunato update-rules`) |
| `install.sh` | `install.sh.minisig` | `kunato upgrade` before the script runs as root |
| `SHA256SUMS` | `SHA256SUMS.minisig` | `kunato upgrade`/the installer when they check downloads |

The trust store lives in `src/trust.rs`. Signing keys never enter the
repository, the build, or CI.

| Key id | Purpose | Added |
| --- | --- | --- |
| `20760B594385E3BB` | release assets | 2026-11-01 |
| `173A1541FCAE2A26` | managed rules | 2026-11-01 |

Both keys are password-protected and live under `~/.config/kunato/keys` on the
signing machine. Record a key id here when a key is added or retired.

## Why minisign

Minisign produces a small Ed25519 signature file next to the artifact, has an
offline-friendly CLI, and allows the verifier to be a few hundred lines with
`ring` (already a dependency). Ed25519 keeps the implementation simple; the
trade-off is that a key file exists on the signing machine while a signature is
being produced (see "Limits" below).

Both variants minisign produces are accepted: plain Ed25519 over the file
(`Ed`) and the prehashed form (`ED`). `minisign -S` uses the prehashed form by
default, hashing the artifact with BLAKE2b-512 first; the digest is implemented
in-tree because `ring` does not expose it.

## Generate the keys

Install the CLI first (Ubuntu/Debian):

```sh
sudo apt-get update
sudo apt-get install -y minisign
```

Then create the key pairs:

```sh
scripts/generate-signing-keys.sh          # ~/.config/kunato/keys
```

This creates `release.key`/`release.pub` and `rules.key`/`rules.pub`, each
protected by its own passphrase. Keep the private keys out of the repository
and back them up (see [Backups](#backups)); only the public keys are pasted into
`src/trust.rs`:

```rust
pub const RELEASE_KEYS: &[&str] = &["untrusted comment: minisign public key ...\nRWQ..."];
pub const RULES_KEYS: &[&str] = &["untrusted comment: minisign public key ...\nRWQ..."];
```

Rebuild after editing the lists. While a list is empty the corresponding check
is skipped with a warning; once a key is listed, a missing or invalid signature
fails closed (the current rules are kept and
`kunato_rules_signature_failure_total` is incremented).

List the **current and the next** key in each array so rotation works without a
window in which old installs reject new signatures.

## Sign

Rules (daily, after `scripts/update-dist-rules.sh`):

```sh
scripts/sign-artifact.sh ~/.config/kunato/keys/rules.key dist/rules.yaml
git add dist/rules.yaml dist/rules.yaml.minisig
```

Release (manual, at release time):

```sh
scripts/sign-artifact.sh ~/.config/kunato/keys/release.key install.sh
scripts/sign-artifact.sh ~/.config/kunato/keys/release.key SHA256SUMS
gh release upload vX.Y.Z install.sh.minisig SHA256SUMS.minisig
```

`dist/rules.yaml.minisig` must be committed together with the rule set: the
updater fetches `<rules url>.minisig` and verifies it over the downloaded bytes.

## Rotation

1. Generate the next key pair and add its public key to the matching list.
2. Release a binary containing both keys.
3. Sign with the new key (and, during the transition, both keys) until installs
   on the previous release have had time to upgrade.
4. Remove the retired key from the list in a later release; record its key id in
   the release notes.

## Backups

The private keys are passphrase-protected, so a stolen backup is not directly
usable. Still:

- Keep a copy in a password manager attachment and an `age`-encrypted copy on
  an offline medium.
- Keep passphrases separate from the key files (paper or a second vault).
- Restore-test once a year by signing a scratch file with the backup key.

## Release checklist

A release that ships a binary with embedded keys must publish signatures, or
installs on that binary will refuse to upgrade (a missing signature is a hard
failure when keys are configured):

1. `scripts/sign-artifact.sh ~/.config/kunato/keys/rules.key dist/rules.yaml`
   and commit `dist/rules.yaml.minisig` (before or with the rules change).
2. After the release workflow publishes the assets, sign and upload the two
   release signatures. `install.sh` and `SHA256SUMS` are **release assets**, not
   repository files (`scripts/install.sh` is the source of the first; the
   second is built by the workflow), so the helper reads `install.sh` from the
   tag and downloads `SHA256SUMS`:
   ```sh
   scripts/sign-release.sh vX.Y.Z
   ```
   The manual equivalent, in a scratch directory:
   ```sh
   dir=$(mktemp -d)
   git show vX.Y.Z:scripts/install.sh >"$dir/install.sh"
   gh release download vX.Y.Z --pattern SHA256SUMS --dir "$dir"
   scripts/sign-artifact.sh ~/.config/kunato/keys/release.key "$dir/install.sh"
   scripts/sign-artifact.sh ~/.config/kunato/keys/release.key "$dir/SHA256SUMS"
   gh release upload vX.Y.Z "$dir/install.sh.minisig" "$dir/SHA256SUMS.minisig"
   ```
3. Sanity-check with the new binary: `kunato update-rules --config ...` against
   the published rules must report the signature as valid.

## Limits

- A freshly installed host still trusts TLS for the first `curl | sudo sh`;
  there is no verifier to bootstrap with. The signature protects upgrades and
  rule updates, not the very first download.
- `install.sh` cannot verify signatures without a Kunato binary; when it is
  re-run on an existing install it can use that binary, otherwise it relies on
  TLS and the checksum.
- Minisign has no token or agent support, so the key is in memory for the
  moment a signature is produced. Keep the signing machine minimal and sign
  only what is about to be published.
- The displayed trusted comment is not authenticated by this verifier; only the
  file signature is checked.
- A rules URL that uses plain HTTP (only accepted for loopback, the documented
  development path) skips the signature check with a warning; HTTPS rules URLs
  enforce it.
