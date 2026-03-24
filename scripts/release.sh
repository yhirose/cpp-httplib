#!/usr/bin/env bash
#
# Release a new version of cpp-httplib.
#
# Usage: ./release.sh [--run]
#
# By default, runs in dry-run mode (no changes made).
# Pass --run to actually update files, commit, tag, and push.
#
# This script:
#   1. Reads the current version from httplib.h
#   2. Checks that the working directory is clean
#   3. Verifies CI status of the latest commit (all must pass except abidiff)
#   4. Determines the next version automatically:
#        - abidiff passed  → patch bump (e.g., 0.38.0 → 0.38.1)
#        - abidiff failed  → minor bump (e.g., 0.38.1 → 0.39.0)
#   5. Updates httplib.h and docs-src/config.toml
#   6. Commits, tags (vX.Y.Z), and pushes

set -euo pipefail

DRY_RUN=1
if [ "${1:-}" = "--run" ]; then
  DRY_RUN=0
  shift
fi

if [ $# -ne 0 ]; then
  echo "Usage: $0 [--run]"
  exit 1
fi

# --- Step 1: Read current version from httplib.h ---
CURRENT_VERSION=$(sed -n 's/^#define CPPHTTPLIB_VERSION "\([^"]*\)"/\1/p' httplib.h)
IFS='.' read -r V_MAJOR V_MINOR V_PATCH <<< "$CURRENT_VERSION"

echo "==> Current version: $CURRENT_VERSION"

# --- Step 2: Check working directory is clean ---
if [ -n "$(git status --porcelain)" ]; then
  echo "Error: working directory is not clean"
  exit 1
fi

# --- Step 3: Check CI status of the latest commit ---
echo ""
echo "==> Checking CI status of the latest commit..."

HEAD_SHA=$(git rev-parse HEAD)
HEAD_SHORT=$(git rev-parse --short HEAD)
echo "    Latest commit: $HEAD_SHORT"

# Fetch all workflow runs for the HEAD commit
RUNS=$(gh run list --json name,conclusion,headSha \
  --jq "[.[] | select(.headSha == \"$HEAD_SHA\")]")

NUM_RUNS=$(echo "$RUNS" | jq 'length')

if [ "$NUM_RUNS" -eq 0 ]; then
  echo "Error: No CI runs found for commit $HEAD_SHORT."
  echo "       Wait for CI to complete before releasing."
  exit 1
fi

echo "    Found $NUM_RUNS workflow run(s):"

FAILED=0
ABIDIFF_PASSED=0
while IFS=$'\t' read -r name conclusion; do
  if [[ "$name" == *abidiff* ]] || [[ "$name" == *abi* && "$name" != *stability* ]]; then
    if [ "$conclusion" = "success" ]; then
      echo "      [ OK ] $name"
      ABIDIFF_PASSED=1
    else
      echo "      [FAIL] $name ($conclusion) → ABI break detected, minor bump"
      ABIDIFF_PASSED=0
    fi
    continue
  fi

  if [ "$conclusion" = "success" ]; then
    echo "      [ OK ] $name"
  else
    echo "      [FAIL] $name ($conclusion)"
    FAILED=1
  fi
done < <(echo "$RUNS" | jq -r '.[] | [.name, .conclusion] | @tsv')

if [ "$FAILED" -eq 1 ]; then
  echo ""
  echo "Error: Some CI checks failed. Fix them before releasing."
  exit 1
fi

echo "    All non-abidiff CI checks passed."

# --- Step 4: Determine new version ---
if [ "$ABIDIFF_PASSED" -eq 1 ]; then
  NEW_PATCH=$((V_PATCH + 1))
  NEW_VERSION="$V_MAJOR.$V_MINOR.$NEW_PATCH"
  echo ""
  echo "==> abidiff passed → patch bump"
else
  NEW_MINOR=$((V_MINOR + 1))
  NEW_VERSION="$V_MAJOR.$NEW_MINOR.0"
  echo ""
  echo "==> abidiff failed → minor bump"
fi

VERSION_HEX=$(printf "0x%02x%02x%02x" "${NEW_VERSION%%.*}" "$(echo "$NEW_VERSION" | cut -d. -f2)" "${NEW_VERSION##*.}")

if [ "$DRY_RUN" -eq 1 ]; then
  echo "==> [DRY RUN] New version: $NEW_VERSION ($VERSION_HEX)"
else
  echo "==> New version: $NEW_VERSION ($VERSION_HEX)"
fi

# --- Step 5: Update files ---
echo ""
if [ "$DRY_RUN" -eq 1 ]; then
  echo "==> [DRY RUN] Would update httplib.h:"
  echo "    CPPHTTPLIB_VERSION     = \"$NEW_VERSION\""
  echo "    CPPHTTPLIB_VERSION_NUM = \"$VERSION_HEX\""
  echo ""
  echo "==> [DRY RUN] Would update docs-src/config.toml:"
  echo "    version = \"$NEW_VERSION\""
  echo ""
  echo "==> [DRY RUN] Would commit, tag v$NEW_VERSION and latest, and push."
  echo ""
  echo "==> Dry run complete. No changes were made."
else
  echo "==> Updating httplib.h..."
  sed -i '' "s/#define CPPHTTPLIB_VERSION \"[^\"]*\"/#define CPPHTTPLIB_VERSION \"$NEW_VERSION\"/" httplib.h
  sed -i '' "s/#define CPPHTTPLIB_VERSION_NUM \"0x[0-9a-fA-F]*\"/#define CPPHTTPLIB_VERSION_NUM \"$VERSION_HEX\"/" httplib.h
  echo "    CPPHTTPLIB_VERSION     = \"$NEW_VERSION\""
  echo "    CPPHTTPLIB_VERSION_NUM = \"$VERSION_HEX\""

  echo ""
  echo "==> Updating docs-src/config.toml..."
  sed -i '' "s/^version = \"[^\"]*\"/version = \"$NEW_VERSION\"/" docs-src/config.toml
  echo "    version = \"$NEW_VERSION\""

  # --- Step 6: Commit, tag, and push ---
  echo ""
  echo "==> Committing and tagging..."
  git add httplib.h docs-src/config.toml
  git commit -m "Release v$NEW_VERSION"
  git tag "v$NEW_VERSION"
  git tag -f "latest"

  echo ""
  echo "==> Pushing..."
  git push && git push --tags --force

  echo ""
  echo "==> Released v$NEW_VERSION"
fi
