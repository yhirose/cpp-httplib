#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# test_book.sh — LLM App Tutorial (Ch1–Ch5) E2E Test
#
# Code is extracted from the doc markdown files (<!-- test:full-code --> and
# <!-- test:cmake --> markers), so tests always stay in sync with the docs.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOCS_DIR="$PROJECT_ROOT/docs-src/pages/ja/llm-app"
WORKDIR=$(mktemp -d)
MODEL_NAME="gemma-2-2b-it-Q4_K_M.gguf"
MODEL_URL="https://huggingface.co/bartowski/gemma-2-2b-it-GGUF/resolve/main/${MODEL_NAME}"
PORT=18080
GECKODRIVER_PORT=4444
SERVER_PID=""
GECKODRIVER_PID=""
PASS_COUNT=0
FAIL_COUNT=0

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [[ -n "$GECKODRIVER_PID" ]]; then
    kill "$GECKODRIVER_PID" 2>/dev/null || true
    wait "$GECKODRIVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { echo "=== $*"; }
pass() { echo "  PASS: $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "  FAIL: $*"; FAIL_COUNT=$((FAIL_COUNT + 1)); }

source "$SCRIPT_DIR/extract_code.sh"

wait_for_server() {
  local max_wait=30
  local i=0
  while ! curl -s -o /dev/null "http://127.0.0.1:${PORT}/" 2>/dev/null; do
    sleep 1
    i=$((i + 1))
    if [[ $i -ge $max_wait ]]; then
      fail "Server did not start within ${max_wait}s"
      return 1
    fi
  done
}

stop_server() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
  fi
}

# Make an HTTP request and capture status + body
# Usage: http_request METHOD PATH [DATA]
# Sets: HTTP_STATUS, HTTP_BODY
http_request() {
  local method="$1" path="$2" data="${3:-}"
  local tmp
  tmp=$(mktemp)
  if [[ -n "$data" ]]; then
    HTTP_STATUS=$(curl -s -o "$tmp" -w '%{http_code}' \
      -X "$method" "http://127.0.0.1:${PORT}${path}" \
      -H "Content-Type: application/json" \
      -d "$data")
  else
    HTTP_STATUS=$(curl -s -o "$tmp" -w '%{http_code}' \
      -X "$method" "http://127.0.0.1:${PORT}${path}")
  fi
  HTTP_BODY=$(cat "$tmp")
  rm -f "$tmp"
}

# Make an SSE request and capture the raw stream
# Usage: http_sse PATH DATA
# Sets: HTTP_STATUS, HTTP_BODY
http_sse() {
  local path="$1" data="$2"
  HTTP_SSE_FILE=$(mktemp)
  HTTP_STATUS=$(curl -s -N -o "$HTTP_SSE_FILE" -w '%{http_code}' \
    -X POST "http://127.0.0.1:${PORT}${path}" \
    -H "Content-Type: application/json" \
    -d "$data")
  HTTP_BODY=$(cat "$HTTP_SSE_FILE")
  rm -f "$HTTP_SSE_FILE"
}

assert_status() {
  local expected="$1" label="$2"
  if [[ "$HTTP_STATUS" == "$expected" ]]; then
    pass "$label (status=$HTTP_STATUS)"
  else
    fail "$label (expected=$expected, got=$HTTP_STATUS)"
    echo "    body: $HTTP_BODY"
  fi
}

assert_json_field() {
  local field="$1" label="$2"
  if echo "$HTTP_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); assert '$field' in d" 2>/dev/null; then
    pass "$label (field '$field' exists)"
  else
    fail "$label (field '$field' missing in response)"
    echo "    body: $HTTP_BODY"
  fi
}

assert_json_value() {
  local field="$1" expected="$2" label="$3"
  local actual
  actual=$(echo "$HTTP_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['$field'])" 2>/dev/null || echo "")
  if [[ "$actual" == "$expected" ]]; then
    pass "$label ($field='$actual')"
  else
    fail "$label (expected $field='$expected', got='$actual')"
  fi
}

assert_json_nonempty() {
  local field="$1" label="$2"
  local val
  val=$(echo "$HTTP_BODY" | python3 -c "import sys,json; v=json.load(sys.stdin)['$field']; assert len(str(v))>0; print(v)" 2>/dev/null || echo "")
  if [[ -n "$val" ]]; then
    pass "$label ($field is non-empty)"
  else
    fail "$label ($field is empty or missing)"
    echo "    body: $HTTP_BODY"
  fi
}

# Patch port number in extracted source code (8080 -> test port)
patch_port() {
  sed "s/127\.0\.0\.1\", 8080/127.0.0.1\", ${PORT}/g; s/127\.0\.0\.1:8080/127.0.0.1:${PORT}/g"
}

# Patch model path in extracted source code
patch_model() {
  sed "s|models/gemma-2-2b-it-Q4_K_M.gguf|models/${MODEL_NAME}|g"
}

# =============================================================================
# Ch1: Skeleton Server
# =============================================================================
test_ch1() {
  log "Ch1: Project Setup & Skeleton Server"

  local APP_DIR="$WORKDIR/translate-app"
  mkdir -p "$APP_DIR/src" "$APP_DIR/models"
  cd "$APP_DIR"

  # Copy httplib.h from project root (test current version)
  cp "$PROJECT_ROOT/httplib.h" .

  # Download json.hpp into nlohmann/ directory to match #include <nlohmann/json.hpp>
  mkdir -p nlohmann
  curl -sL -o nlohmann/json.hpp \
    https://github.com/nlohmann/json/releases/latest/download/json.hpp

  # CMakeLists.txt — ch1 doesn't need llama.cpp, so use a minimal version
  # (the doc's cmake includes llama.cpp which isn't cloned yet in ch1)
  cat > CMakeLists.txt << 'CMAKE_EOF'
cmake_minimum_required(VERSION 3.16)
project(translate-server LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)

add_executable(translate-server src/main.cpp)
target_include_directories(translate-server PRIVATE ${CMAKE_SOURCE_DIR})
CMAKE_EOF

  # Extract main.cpp from ch1 doc and patch port
  extract_code "$DOCS_DIR/ch01-setup.md" "main.cpp" | patch_port > src/main.cpp

  # Build
  log "Ch1: Building..."
  cmake -B build -DCMAKE_BUILD_TYPE=Release 2>&1 | tail -1
  cmake --build build -j 2>&1 | tail -3

  # Start server
  ./build/translate-server &
  SERVER_PID=$!
  wait_for_server

  # Tests
  http_request POST /translate '{"text":"hello","target_lang":"ja"}'
  assert_status 200 "Ch1 POST /translate"
  assert_json_value translation "TODO" "Ch1 POST /translate returns TODO"

  http_request GET /models
  assert_status 200 "Ch1 GET /models"
  assert_json_field models "Ch1 GET /models"

  http_request POST /models/select '{"model":"test"}'
  assert_status 200 "Ch1 POST /models/select"
  assert_json_value status "TODO" "Ch1 POST /models/select returns TODO"

  stop_server
  log "Ch1: Done"
}

# =============================================================================
# Ch2: REST API with llama.cpp
# =============================================================================
test_ch2() {
  log "Ch2: REST API with llama.cpp"

  local APP_DIR="$WORKDIR/translate-app"
  cd "$APP_DIR"

  # Clone llama.cpp
  if [[ ! -d llama.cpp ]]; then
    log "Ch2: Cloning llama.cpp..."
    git clone --depth 1 https://github.com/ggml-org/llama.cpp.git 2>&1 | tail -1
  fi

  # Download cpp-llamalib.h
  if [[ ! -f cpp-llamalib.h ]]; then
    curl -sL -o cpp-llamalib.h \
      https://raw.githubusercontent.com/yhirose/cpp-llamalib/main/cpp-llamalib.h
  fi

  # Download model
  if [[ ! -f "models/$MODEL_NAME" ]]; then
    log "Ch2: Downloading model ${MODEL_NAME} (~1.6GB)..."
    curl -L -o "models/$MODEL_NAME" "$MODEL_URL"
  fi

  # CMakeLists.txt from ch1 doc (includes llama.cpp)
  extract_code "$DOCS_DIR/ch01-setup.md" "CMakeLists.txt" > CMakeLists.txt

  # Extract main.cpp from ch2 doc and patch port + model path
  extract_code "$DOCS_DIR/ch02-rest-api.md" "main.cpp" | patch_port | patch_model > src/main.cpp

  # Build (clean rebuild needed — cmake config changed)
  log "Ch2: Building (this may take a while for llama.cpp)..."
  rm -rf build
  cmake -B build -DCMAKE_BUILD_TYPE=Release 2>&1 | tail -1
  cmake --build build -j 2>&1 | tail -3

  # Start server
  ./build/translate-server &
  SERVER_PID=$!
  wait_for_server

  # Tests — normal request
  http_request POST /translate \
    '{"text":"I had a great time visiting Tokyo last spring. The cherry blossoms were beautiful.","target_lang":"ja"}'
  assert_status 200 "Ch2 POST /translate normal"
  assert_json_nonempty translation "Ch2 POST /translate has translation"

  # Tests — invalid JSON
  http_request POST /translate 'not json'
  assert_status 400 "Ch2 POST /translate invalid JSON"

  # Tests — missing text
  http_request POST /translate '{"target_lang":"ja"}'
  assert_status 400 "Ch2 POST /translate missing text"

  # Tests — empty text
  http_request POST /translate '{"text":""}'
  assert_status 400 "Ch2 POST /translate empty text"

  stop_server
  log "Ch2: Done"
}

# =============================================================================
# Ch3: SSE Streaming
# =============================================================================
test_ch3() {
  log "Ch3: SSE Streaming"

  local APP_DIR="$WORKDIR/translate-app"
  cd "$APP_DIR"

  # Extract main.cpp from ch3 doc and patch port + model path
  extract_code "$DOCS_DIR/ch03-sse-streaming.md" "main.cpp" | patch_port | patch_model > src/main.cpp

  # Build (incremental — only main.cpp changed)
  log "Ch3: Building..."
  cmake --build build -j 2>&1 | tail -3

  # Start server
  ./build/translate-server &
  SERVER_PID=$!
  wait_for_server

  # Tests — /translate still works
  http_request POST /translate \
    '{"text":"Hello world","target_lang":"ja"}'
  assert_status 200 "Ch3 POST /translate still works"

  # Tests — SSE streaming
  http_sse /translate/stream \
    '{"text":"I had a great time visiting Tokyo last spring. The cherry blossoms were beautiful.","target_lang":"ja"}'
  assert_status 200 "Ch3 POST /translate/stream status"

  # Check SSE format: has data: lines and ends with [DONE]
  local data_lines
  data_lines=$(echo "$HTTP_BODY" | grep -c '^data: ' || true)
  if [[ $data_lines -ge 2 ]]; then
    pass "Ch3 SSE has multiple data: lines ($data_lines)"
  else
    fail "Ch3 SSE expected multiple data: lines, got $data_lines"
    echo "    body: $HTTP_BODY"
  fi

  if echo "$HTTP_BODY" | grep -q 'data: \[DONE\]'; then
    pass "Ch3 SSE ends with data: [DONE]"
  else
    fail "Ch3 SSE missing data: [DONE]"
    echo "    body: $HTTP_BODY"
  fi

  # Tests — SSE invalid JSON
  http_sse /translate/stream 'not json'
  assert_status 400 "Ch3 POST /translate/stream invalid JSON"

  stop_server
  log "Ch3: Done"
}

# =============================================================================
# Ch4: Model Management
# =============================================================================
test_ch4() {
  log "Ch4: Model Management"

  local APP_DIR="$WORKDIR/translate-app"
  cd "$APP_DIR"

  # Ch4+ uses ~/.translate-app/models/ — symlink model there
  local MODELS_HOME="$HOME/.translate-app/models"
  mkdir -p "$MODELS_HOME"
  ln -sf "$APP_DIR/models/$MODEL_NAME" "$MODELS_HOME/$MODEL_NAME"

  # CMakeLists.txt from ch4 (adds OpenSSL)
  extract_code "$DOCS_DIR/ch04-model-management.md" "CMakeLists.txt" > CMakeLists.txt

  # Extract main.cpp from ch4 doc
  extract_code "$DOCS_DIR/ch04-model-management.md" "main.cpp" | patch_port > src/main.cpp

  # Build (reconfigure for OpenSSL, incremental — reuses llama.cpp objects)
  log "Ch4: Building..."
  cmake -B build -DCMAKE_BUILD_TYPE=Release 2>&1 | tail -1
  cmake --build build -j 2>&1 | tail -3

  # Start server
  ./build/translate-server &
  SERVER_PID=$!
  wait_for_server

  # Tests — GET /models
  http_request GET /models
  assert_status 200 "Ch4 GET /models"
  assert_json_field models "Ch4 GET /models has models array"

  # デフォルトモデルがdownloaded+selectedであること
  local selected
  selected=$(echo "$HTTP_BODY" | python3 -c "
import sys, json
models = json.load(sys.stdin)['models']
sel = [m for m in models if m['selected']]
print(sel[0]['downloaded'] if sel else '')
" 2>/dev/null || echo "")
  if [[ "$selected" == "True" ]]; then
    pass "Ch4 GET /models default model is downloaded and selected"
  else
    fail "Ch4 GET /models default model state unexpected"
    echo "    body: $HTTP_BODY"
  fi

  # Tests — POST /models/select with already-downloaded model (SSE)
  http_sse /models/select '{"model": "gemma-2-2b-it"}'
  assert_status 200 "Ch4 POST /models/select already downloaded"

  if echo "$HTTP_BODY" | grep -q '"ready"'; then
    pass "Ch4 POST /models/select returns ready"
  else
    fail "Ch4 POST /models/select missing ready status"
    echo "    body: $HTTP_BODY"
  fi

  # Tests — POST /models/select unknown model
  http_request POST /models/select '{"model": "nonexistent"}'
  assert_status 404 "Ch4 POST /models/select unknown model"

  # Tests — POST /models/select missing model field
  http_request POST /models/select '{"foo": "bar"}'
  assert_status 400 "Ch4 POST /models/select missing model field"

  # Tests — /translate still works after model select
  http_request POST /translate '{"text": "Hello", "target_lang": "ja"}'
  assert_status 200 "Ch4 POST /translate still works"
  assert_json_nonempty translation "Ch4 POST /translate has translation"

  # Tests — switch model via symlink (avoids downloading a second model)
  # Place a symlink so the server sees Llama-3.1-8B-Instruct as "downloaded"
  ln -sf "$MODELS_HOME/$MODEL_NAME" "$MODELS_HOME/Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf"

  http_sse /models/select '{"model": "Llama-3.1-8B-Instruct"}'
  assert_status 200 "Ch4 POST /models/select switch model"

  if echo "$HTTP_BODY" | grep -q '"ready"'; then
    pass "Ch4 model switch returns ready"
  else
    fail "Ch4 model switch missing ready"
    echo "    body: $HTTP_BODY"
  fi

  # Translate with the switched model
  http_request POST /translate \
    '{"text": "The weather is nice today.", "target_lang": "ja"}'
  assert_status 200 "Ch4 POST /translate after model switch"
  assert_json_nonempty translation "Ch4 POST /translate switched model has translation"

  # Verify model list reflects the switch
  http_request GET /models
  local new_selected
  new_selected=$(echo "$HTTP_BODY" | python3 -c "
import sys, json
models = json.load(sys.stdin)['models']
sel = [m for m in models if m['selected']]
print(sel[0]['name'] if sel else '')
" 2>/dev/null || echo "")
  if [[ "$new_selected" == "Llama-3.1-8B-Instruct" ]]; then
    pass "Ch4 GET /models reflects model switch"
  else
    fail "Ch4 GET /models expected Llama-3.1-8B-Instruct selected, got '$new_selected'"
  fi

  stop_server
  log "Ch4: Done"
}

# =============================================================================
# Ch5: Web UI (browser tests via geckodriver + webdriver.h)
# =============================================================================

start_geckodriver() {
  geckodriver --port "$GECKODRIVER_PORT" &>/dev/null &
  GECKODRIVER_PID=$!
  # Wait for geckodriver to be ready
  local i=0
  while ! curl -s -o /dev/null "http://127.0.0.1:${GECKODRIVER_PORT}/status" 2>/dev/null; do
    sleep 0.5
    i=$((i + 1))
    if [[ $i -ge 20 ]]; then
      fail "geckodriver did not start within 10s"
      return 1
    fi
  done
}

stop_geckodriver() {
  if [[ -n "$GECKODRIVER_PID" ]]; then
    kill "$GECKODRIVER_PID" 2>/dev/null || true
    wait "$GECKODRIVER_PID" 2>/dev/null || true
    GECKODRIVER_PID=""
  fi
}

test_ch5() {
  log "Ch5: Web UI (browser tests)"

  # Check for geckodriver
  if ! command -v geckodriver &>/dev/null; then
    log "Ch5: Skipping browser tests (geckodriver not found)"
    log "Ch5: Install with: brew install geckodriver"
    return 0
  fi

  local APP_DIR="$WORKDIR/translate-app"
  cd "$APP_DIR"

  # Extract source files from ch05
  extract_code "$DOCS_DIR/ch05-web-ui.md" "main.cpp" \
    | patch_port > src/main.cpp

  mkdir -p public
  extract_code "$DOCS_DIR/ch05-web-ui.md" "index.html"  > public/index.html
  extract_code "$DOCS_DIR/ch05-web-ui.md" "style.css"   > public/style.css
  extract_code "$DOCS_DIR/ch05-web-ui.md" "script.js"   > public/script.js

  # Build (incremental — only main.cpp changed)
  log "Ch5: Building server..."
  cmake --build build -j 2>&1 | tail -3

  # Build browser test program
  log "Ch5: Building browser test..."
  g++ -std=c++17 \
    -I"$APP_DIR" \
    -I"$SCRIPT_DIR" \
    -o "$APP_DIR/build/test_webui" \
    "$SCRIPT_DIR/test_webui.cpp" \
    -pthread

  # Start server
  ./build/translate-server &
  SERVER_PID=$!
  wait_for_server

  # Start geckodriver
  start_geckodriver

  # Run browser tests
  log "Ch5: Running browser tests..."
  local test_exit=0
  "$APP_DIR/build/test_webui" "$PORT" || test_exit=$?

  # Parse pass/fail from test output and add to totals
  # (test_webui prints its own pass/fail, but we track via exit code)
  if [[ $test_exit -ne 0 ]]; then
    fail "Ch5 browser tests had failures"
  else
    pass "Ch5 browser tests all passed"
  fi

  stop_geckodriver
  stop_server
  log "Ch5: Done"
}

# =============================================================================
# Main
# =============================================================================

log "LLM App Tutorial E2E Test"
log "Working directory: $WORKDIR"
echo ""

test_ch1
echo ""
test_ch2
echo ""
test_ch3
echo ""
test_ch4
echo ""
test_ch5

log "Results: $PASS_COUNT passed, $FAIL_COUNT failed"

if [[ $FAIL_COUNT -gt 0 ]]; then
  exit 1
fi
