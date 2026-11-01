# Signing key backup

The release and rules signing keys exist only on the maintainer's machine and,
for the rules key, in the write-only `RULES_SIGNING_KEY` GitHub environment
secret. A GitHub secret cannot be read back, so a lost local key cannot be
recovered from GitHub: the backup is the only recovery path. This page is the
procedure for creating, storing, and testing that backup.

## What to back up

| Item | Location | Notes |
| --- | --- | --- |
| `release.key` | `~/.config/kunato/keys/` | passphrase-protected minisign secret key |
| `rules.key` | `~/.config/kunato/keys/` | passphrase-protected; also stored in the `rules-signing` environment |
| `release.pub`, `rules.pub` | same directory | public; also recorded in `src/trust.rs` and [release-signing.md](release-signing.md) |
| minisign passphrases | password manager / paper | one per key, never next to the key file |
| `age` passphrase | paper / separate vault | protects the encrypted archive below |

Keeping the archive and its passphrase together defeats the encryption. Treat
them as two separate secrets in two separate places.

## Create the backup

Install `age` first (Ubuntu/Debian):

```sh
sudo apt-get update
sudo apt-get install -y age
```

Create the archive without writing a plaintext copy to disk:

```sh
ts=$(date +%F)
umask 077
tar -C "$HOME/.config/kunato" -czf - keys \
  | age -p -o "$HOME/kunato-signing-keys-$ts.tar.gz.age"
```

`age -p` asks for a passphrase twice; use a passphrase that is different from
both minisign passphrases. Record the checksum:

```sh
sha256sum "$HOME/kunato-signing-keys-$ts.tar.gz.age"
```

Confirm the archive decrypts and lists the expected files (this only prints the
file names, it does not extract them):

```sh
age -d "$HOME/kunato-signing-keys-$ts.tar.gz.age" | tar -tzf -
# keys/release.key
# keys/release.pub
# keys/rules.key
# keys/rules.pub
```

## Store it in three places

| Place | Contents |
| --- | --- |
| Password manager | the `.age` file as an attachment (encrypted vault) |
| Offline USB stick | the `.age` file only; unmounted when not in use |
| Off-site / second USB | the `.age` file, or a yearly refresh checklist (never the key itself on paper) |

Rules:

- Keep the `age` passphrase away from the archive (paper in another location, or
  a second vault).
- Do not put the `.age` file, a key, or a passphrase in the repository, in chat,
  in a cloud share link, or in the same USB directory as a passphrase note.
- Record the backup date and checksum in the password manager.

## Restore test (once a year)

A backup that has never been restored is an assumption. Run this yearly, or
after any key change:

```sh
mkdir -p /tmp/restore
age -d "$HOME/kunato-signing-keys-$ts.tar.gz.age" | tar -xzf - -C /tmp/restore
chmod 700 /tmp/restore/keys

printf 'restore test\n' >/tmp/restore-test.txt
minisign -S -s /tmp/restore/keys/rules.key -m /tmp/restore-test.txt \
  -x /tmp/restore-test.sig
minisign -Vm /tmp/restore-test.txt -p "$HOME/.config/kunato/keys/rules.pub"

shred -u /tmp/restore/keys/*.key /tmp/restore-test.txt /tmp/restore-test.sig
rm -rf /tmp/restore
```

Repeat for `release.key`. The signature must verify against the matching public
key.

## Operational rules

- **Rotate, then re-back up the same day.** Destroy the previous `.age` file
  once the new one is stored in all three places.
- **Never rely on the GitHub secret as a backup.** It can be replaced but not
  read; losing the local key means the key cannot be used for manual signing or
  rotation.
- **Losing the backup is not fatal for delivery** as long as the key still works
  in CI, but it blocks rotation and offline signing until a new key pair is
  generated and embedded in a release.
- **Delete temporary plaintext.** Use `shred -u` for extracted keys and test
  signatures.
- **Check the directory mode**: `~/.config/kunato/keys` must stay `0700` and the
  key files `0600`.

## Alternatives

If `age` is unavailable, any authenticated encryption tool works, as long as the
plaintext is never written to disk:

```sh
# GPG, symmetric
tar -C "$HOME/.config/kunato" -czf - keys | gpg --symmetric --cipher-algo AES256 \
  -o "$HOME/kunato-signing-keys-$ts.tar.gz.gpg"

# OpenSSL
tar -C "$HOME/.config/kunato" -czf - keys | openssl enc -aes-256-cbc -pbkdf2 \
  -salt -out "$HOME/kunato-signing-keys-$ts.tar.gz.enc"
```

Decrypt with the matching tool during the restore test. `age -p` is preferred
because it is small, has a modern passphrase KDF, and produces a single file.
