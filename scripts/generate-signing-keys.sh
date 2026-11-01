#!/bin/sh
# Generate the release and rules minisign key pairs outside the repository.
#
# Run this once on the signing machine. The secret keys stay under
# ~/.config/kunato/keys by default (mode 700) and must be backed up encrypted;
# only the public keys are pasted into src/trust.rs and committed.
set -eu

dir=${1:-"$HOME/.config/kunato/keys"}

command -v minisign >/dev/null 2>&1 || {
    echo "minisign is required" >&2
    exit 1
}
mkdir -p "$dir"
chmod 700 "$dir"

for purpose in release rules; do
    if [ -e "$dir/$purpose.key" ]; then
        echo "refusing to overwrite $dir/$purpose.key" >&2
        exit 1
    fi
    echo "generating the $purpose key pair (choose a strong passphrase)"
    minisign -G -p "$dir/$purpose.pub" -s "$dir/$purpose.key"
done

echo
echo "Keys written under $dir (directory mode 0700)."
echo "Back up the .key files encrypted and never commit them."
echo
echo "Paste each public key into the matching list in src/trust.rs:"
for purpose in release rules; do
    echo "--- $purpose.pub ---"
    cat "$dir/$purpose.pub"
    echo
done
