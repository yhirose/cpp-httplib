#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$SCRIPT_DIR/build/web-app"
DOCS_DIR="$SCRIPT_DIR/../../docs-src/pages/ja/llm-app"

source "$SCRIPT_DIR/extract_code.sh"

echo "=== Setting up Web App (Chapter 5) ==="

mkdir -p "$OUT_DIR"/{src,public}
cd "$OUT_DIR"

# --- Extract source files from book ---
echo "Extracting source from book..."
CH04="$DOCS_DIR/ch04-model-management.md"
CH05="$DOCS_DIR/ch05-web-ui.md"

extract_code "$CH04" "CMakeLists.txt" > CMakeLists.txt
extract_code "$CH05" "main.cpp"       > src/main.cpp
extract_code "$CH05" "index.html"     > public/index.html
extract_code "$CH05" "style.css"      > public/style.css
extract_code "$CH05" "script.js"      > public/script.js

# --- Build ---
echo "Building..."
cmake -B build 2>&1 | tail -1
cmake --build build -j 2>&1 | tail -1

echo ""
echo "=== Done ==="
echo "Run: cd $OUT_DIR && ./build/translate-server"
