#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
REPO_ROOT="${DT_REPO_ROOT:-$(cd "$PROJECT/../.." && pwd -P)}"
ARCHIVE="${DT_102739K_ARCHIVE:-$REPO_ROOT/tvOS/tvbootstrap-ssh-1900.tar.zst}"
OUT="${1:-$PROJECT/bootstrap_preflight/BUILD102739K_CF1900_PATHS.tsv}"
EXPECTED_SHA="54299aaf56176695b4fe6883f13bd67617d8c008e5bc5778591ec3940e5e7666"
EXPECTED_MEMBERS=4041
EXPECTED_PATHS=4040
WORK="$(mktemp -d /tmp/dt102739k_manifest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

[[ -f "$ARCHIVE" ]]
actual_sha="$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')"
[[ "$actual_sha" == "$EXPECTED_SHA" ]]
zstd -t "$ARCHIVE" >/dev/null

tar --zstd -tf "$ARCHIVE" > "$WORK/names"
tar --zstd -tvf "$ARCHIVE" | cut -c1 > "$WORK/types"
[[ "$(wc -l < "$WORK/names" | tr -d ' ')" -eq "$EXPECTED_MEMBERS" ]]
[[ "$(wc -l < "$WORK/types" | tr -d ' ')" -eq "$EXPECTED_MEMBERS" ]]
if LC_ALL=C rg -q '[[:space:]]' "$WORK/names"; then
    echo "ERROR: archive member name contains whitespace" >&2
    exit 1
fi
if rg -q '(^/|(^|/)\.\.(/|$))' "$WORK/names"; then
    echo "ERROR: archive member escapes the rootful payload namespace" >&2
    exit 1
fi
if rg -v '^[dl-]$' "$WORK/types"; then
    echo "ERROR: unsupported archive member type" >&2
    exit 1
fi

paste "$WORK/types" "$WORK/names" \
    | awk -F '\t' '
        $2 == "./" { next }
        {
            path = $2
            sub(/^\.\//, "", path)
            sub(/\/$/, "", path)
            if (path == "") next
            split(path, part, "/")
            if (!(part[1] == ".procursus_strapped" || part[1] == "Library" ||
                  part[1] == "bin" || part[1] == "boot" || part[1] == "lib" ||
                  part[1] == "mnt" || part[1] == "prep_bootstrap.sh" ||
                  part[1] == "private" || part[1] == "sbin" || part[1] == "usr")) {
                print "ERROR: unexpected top-level path " path > "/dev/stderr"
                exit 2
            }
            print $1 "\t/" path
        }
    ' > "$WORK/entries"

[[ "$(wc -l < "$WORK/entries" | tr -d ' ')" -eq "$EXPECTED_PATHS" ]]
[[ "$(cut -f2 "$WORK/entries" | sort -u | wc -l | tr -d ' ')" -eq "$EXPECTED_PATHS" ]]

mkdir -p "$(dirname "$OUT")"
{
    echo '#FORMAT=TYPE_TAB_NORMALIZED_ABSOLUTE_PATH_V1'
    echo '#TARGET_MODEL=AppleTV6,2'
    echo '#TARGET_OS=16.5'
    echo '#TARGET_BUILD=20L563'
    echo '#BOOTSTRAP_FAMILY=appletvos-arm64'
    echo '#BOOTSTRAP_CF_VERSION=1900'
    echo "#ARCHIVE_SHA256=$EXPECTED_SHA"
    echo "#ARCHIVE_MEMBER_COUNT=$EXPECTED_MEMBERS"
    echo "#INVENTORY_PATH_COUNT=$EXPECTED_PATHS"
    cat "$WORK/entries"
} > "$OUT"

echo "BUILD102739K_MANIFEST_PATH=$OUT"
echo "BUILD102739K_MANIFEST_SHA256=$(shasum -a 256 "$OUT" | awk '{print $1}')"
echo "BUILD102739K_MANIFEST_RESULT=PASS"
