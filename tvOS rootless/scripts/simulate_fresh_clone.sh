#!/bin/bash
# Simulate fresh-machine clone without git: copy source-only tree to isolated path.
set -euo pipefail
SRC="/Volumes/Untitled2/Apple TV Project/tvOS rootless"
DST="${1:-/tmp/tvos-rootless-fresh-clone}"
BUILD="${2:-/tmp/tvos-rootless-repro-build}"

rm -rf "$DST" "$BUILD"
mkdir -p "$DST"

rsync -a \
  --exclude='.git/' \
  --exclude='.theos' \
  --exclude='source/.theos' \
  --exclude='source/build' \
  --exclude='source/basebin/out' \
  --exclude='vendor/dyld/user/' \
  --exclude='bootstrap/tars/' \
  --exclude='.DS_Store' \
  "$SRC/" "$DST/"

mkdir -p "$DST/bootstrap/tars" "$DST/vendor/dyld/user"
echo "FRESH_CLONE_SOURCE=$DST"
echo "FRESH_BUILD_ROOT=$BUILD"
