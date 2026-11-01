#!/bin/sh
# Sign the published assets of a GitHub release.
#
# install.sh is published verbatim from scripts/install.sh at the tag, so it is
# signed from the tag's tree. SHA256SUMS only exists as a release asset (the
# workflow builds it), so it is downloaded first. Both signatures are uploaded
# next to the assets.
#
# Usage:
#   scripts/sign-release.sh vX.Y.Z
#
# The release key defaults to ~/.config/kunato/keys/release.key and can be
# overridden with KUNATO_RELEASE_KEY.
set -eu

[ $# -eq 1 ] || {
    echo "usage: $0 <tag>" >&2
    exit 2
}
tag=$1
key=${KUNATO_RELEASE_KEY:-"$HOME/.config/kunato/keys/release.key"}

for tool in gh minisign git; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "$tool is required" >&2
        exit 1
    }
done
[ -f "$key" ] || {
    echo "release key not found: $key" >&2
    exit 1
}

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT INT TERM

# Sign exactly what the tag published, not an uncommitted local copy.
git show "$tag:scripts/install.sh" >"$dir/install.sh" || {
    echo "cannot read scripts/install.sh at $tag (git fetch --tags?)" >&2
    exit 1
}
gh release download "$tag" --pattern SHA256SUMS --dir "$dir" --clobber

scripts/sign-artifact.sh "$key" "$dir/install.sh"
scripts/sign-artifact.sh "$key" "$dir/SHA256SUMS"

gh release upload "$tag" "$dir/install.sh.minisig" "$dir/SHA256SUMS.minisig" --clobber
echo "uploaded signatures for $tag"
