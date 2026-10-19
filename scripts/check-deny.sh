#!/bin/sh
# Run cargo-deny for every target configured in deny.toml.
#
# cargo-deny only passes `--filter-platform` to `cargo metadata` when exactly
# one target is configured. With several targets it resolves dependencies for
# every platform, including Android-only crates that may not be cached. This
# wrapper runs one target at a time and points the advisory database at a
# temporary writable copy, so the audit also works when $CARGO_HOME is on a
# read-only filesystem (for example inside a build sandbox).
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

command -v cargo >/dev/null 2>&1 || {
    echo "check-deny: cargo is required" >&2
    exit 1
}
command -v cargo-deny >/dev/null 2>&1 || {
    echo "check-deny: cargo-deny is required (cargo install cargo-deny)" >&2
    exit 1
}

targets=$(sed -n 's/.*triple[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' deny.toml)
[ -n "$targets" ] || {
    echo "check-deny: no target triples found in deny.toml" >&2
    exit 1
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

db="$work/advisory-dbs"
mkdir -p "$db"
cargo_home=${CARGO_HOME:-$HOME/.cargo}
db_found=0
if [ -d "$cargo_home/advisory-dbs" ]; then
    for source in "$cargo_home"/advisory-dbs/advisory-db-*; do
        [ -d "$source" ] || continue
        cp -a "$source" "$db/"
        db_found=1
    done
fi

# Build a config with a writable advisory DB path. Drop any existing db-path
# line so the generated config has exactly one.
config="$work/deny.toml"
grep -v '^[[:space:]]*db-path[[:space:]]*=' deny.toml |
    awk -v path="$db" '
        /^\[advisories\]/ { print; print "db-path = \"" path "\""; found = 1; next }
        { print }
        END {
            if (!found) {
                print "[advisories]"
                print "db-path = \"" path "\""
            }
        }
    ' > "$config"

if [ "$db_found" -eq 0 ]; then
    echo "check-deny: fetching the advisory database"
    cargo deny --config "$config" fetch
fi

printf '%s\n' "$targets" > "$work/targets"
status=0
while IFS= read -r target; do
    [ -n "$target" ] || continue
    echo "check-deny: $target"
    cargo deny --offline --locked --config "$config" -t "$target" check || status=1
done < "$work/targets"
exit "$status"
