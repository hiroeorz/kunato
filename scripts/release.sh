#!/bin/sh
# Cut a release: bump the package version, commit and push it, then tag the
# commit and push the tag. The tag push builds and publishes the binaries
# through .github/workflows/release.yml.
#
# Run from anywhere inside the repository. The release is always cut from
# `main`, which must be clean and match origin/main.
set -eu

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
repo="hiroeorz/kunato"

log() { printf 'kunato-release: %s\n' "$*"; }
die() {
    printf 'kunato-release: error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Cut a Kunato release.

Usage:
  scripts/release.sh [--dry-run] [--skip-checks] X.Y.Z

The version may be written with or without the leading v. The script requires
a clean `main` that matches origin/main, runs the local checks (fmt, clippy,
deny, test) unless --skip-checks is given, bumps the Cargo.toml version,
commits and pushes it, and then tags and pushes vX.Y.Z. The tag push triggers
the release workflow.

--dry-run performs every step except the commit, tag, and pushes, and
restores the working tree afterwards.
EOF
}

dry_run=0
skip_checks=0
version_arg=""
for arg in "$@"; do
    case "$arg" in
        --dry-run) dry_run=1 ;;
        --skip-checks) skip_checks=1 ;;
        -h | --help)
            usage
            exit 0
            ;;
        -*)
            die "unknown option: $arg"
            ;;
        *)
            [ -z "$version_arg" ] || die "unexpected extra argument: $arg"
            version_arg="$arg"
            ;;
    esac
done
[ -n "$version_arg" ] || die "missing version argument (see --help)"

version="${version_arg#v}"
printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' ||
    die "version must be X.Y.Z, got: $version_arg"

command -v git >/dev/null 2>&1 || die "git is required"
command -v cargo >/dev/null 2>&1 || die "cargo is required"

cd "$root"

[ "$(git branch --show-current)" = "main" ] || die "releases are cut from main"
[ -z "$(git status --porcelain)" ] || die "the working tree is not clean"
git fetch --quiet origin
[ "$(git rev-parse main)" = "$(git rev-parse origin/main)" ] ||
    die "main and origin/main differ; pull or push first"

current=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
[ -n "$current" ] || die "could not read the package version from Cargo.toml"
[ "$version" != "$current" ] || die "Cargo.toml is already at $version"
if git rev-parse -q --verify "refs/tags/v$version" >/dev/null; then
    die "tag v$version already exists locally"
fi
if git ls-remote --exit-code --tags origin "refs/tags/v$version" >/dev/null 2>&1; then
    die "tag v$version already exists on origin"
fi

if [ "$skip_checks" -eq 0 ]; then
    log "running fmt, clippy, deny, and tests"
    cargo fmt --check
    cargo clippy --all-targets -- -D warnings
    cargo deny check
    cargo test
fi

restore() {
    git checkout -- Cargo.toml Cargo.lock 2>/dev/null || true
}
if [ "$dry_run" -eq 1 ]; then
    trap restore EXIT
fi

log "bumping the package version to $version"
tmp="$root/Cargo.toml.tmp"
awk -v version="$version" '
    !updated && /^version = "/ { sub(/"[^"]*"/, "\"" version "\""); updated = 1 }
    { print }
' "$root/Cargo.toml" >"$tmp"
mv "$tmp" "$root/Cargo.toml"
grep -q "^version = \"$version\"$" "$root/Cargo.toml" ||
    die "failed to update the package version"
cargo metadata --format-version 1 >/dev/null
grep -A1 '^name = "kunato"$' Cargo.lock | grep -q "^version = \"$version\"$" ||
    die "failed to update Cargo.lock"

if [ "$dry_run" -eq 1 ]; then
    log "dry run: would commit 'Release v$version', push main, and push tag v$version"
    exit 0
fi

git add Cargo.toml Cargo.lock
git commit -m "Release v$version" -m "Bump the package version so the tagged build reports $version."
git push origin main
git tag "v$version"
git push origin "v$version"

log "released v$version"
log "watch the build: https://github.com/$repo/actions/workflows/release.yml"
