#!/bin/bash
# Generate the desktop app project by extracting source from the cpp-httplib book.
# Usage: generate_desktop_app_project.sh <output-dir>
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${1:?Usage: $0 <output-dir>}"

BASE_URL="https://raw.githubusercontent.com/yhirose/cpp-httplib/master/docs-src/pages/ja/llm-app"
CACHE_DIR="$SCRIPT_DIR/.cache"

source "$SCRIPT_DIR/extract_code.sh"

# --- Helper: download markdown files (always fetch latest) ---
fetch_md() {
  local name="$1"
  local path="$CACHE_DIR/$name"
  curl -sfL "$BASE_URL/$name" -o "$path" || { echo "ERROR: Failed to download $name" >&2; return 1; }
  echo "$path"
}

# --- Main ---
echo "=== Generating desktop app project ==="

mkdir -p "$CACHE_DIR" "$OUT_DIR/src" "$OUT_DIR/public"

CH05=$(fetch_md "ch05-web-ui.md")
CH06=$(fetch_md "ch06-desktop-app.md")

echo "Extracting source files..."
extract_code "$CH06" "CMakeLists.txt" > "$OUT_DIR/CMakeLists.txt"
extract_code "$CH06" "main.cpp"       > "$OUT_DIR/src/main.cpp"
extract_code "$CH05" "index.html"     > "$OUT_DIR/public/index.html"
extract_code "$CH05" "style.css"      > "$OUT_DIR/public/style.css"
extract_code "$CH05" "script.js"      > "$OUT_DIR/public/script.js"

echo "=== Done ==="
echo "Generated files in: $OUT_DIR"
