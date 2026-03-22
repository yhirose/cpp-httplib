---
title: "5. Adding a Web UI"
order: 5

---

By the end of Chapter 4, we've built out all the server features: the translation API, SSE streaming, and model management. But so far, the only way to interact with it is through curl. In this chapter, we'll add a Web UI so you can translate from the browser.

Here's what the finished screen looks like.

![Web UI](../webui.png#large-center)

- As you type text, tokens appear one by one (with debounce)
- You can switch models and languages from the header dropdowns
- Selecting an undownloaded model starts a download with a progress bar (cancellable)

The HTML, CSS, and JavaScript code is minimal. We won't use any CSS framework -- just plain CSS (about 100 lines) for the layout. Since this is a C++ book, we won't go into detailed frontend explanations. We'll just show you "write this, and it does that."

## 5.1 File Structure

These are the files we'll add in this chapter. We'll place HTML, CSS, and JavaScript in the `public/` directory and serve them from the server.

```ascii
translate-app/
├── public/
│   ├── index.html
│   ├── style.css
│   └── script.js
└── src/
    └── main.cpp      # Add set_mount_point
```

## 5.2 Setting Up Static File Serving

Using cpp-httplib's `set_mount_point`, you can serve a directory directly over HTTP. Create a `public/` directory and place an empty `index.html` in it.

```bash
mkdir public
```

```html
<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>Translate App</title>
</head>
<body>
  <h1>Hello!</h1>
</body>
</html>
```

Add one line of `set_mount_point` to the server code and rebuild.

```cpp
// Add inside `main()`, before `svr.listen()`
svr.set_mount_point("/", "./public");
```

Start the server and open `http://127.0.0.1:8080` in your browser -- you should see "Hello!" displayed. Since these are static files, just reload the browser after editing `index.html` to see the changes. No server restart needed.

## 5.3 Building the Layout

Replace `index.html` with the final layout.

```html
<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Translate App</title>
  <!-- Set favicon with inline SVG emoji (no image file needed) -->
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🌐</text></svg>">
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <!-- Header: title + model selector + language selector -->
  <header>
    <strong>Translate App</strong>
    <div>
      <!-- Options are dynamically populated by script.js via `GET /models` -->
      <select id="model-select" aria-label="Model"></select>
      <select id="target-lang" aria-label="Target language">
        <option value="ja">Japanese</option>
        <option value="en">English</option>
        <option value="zh">Chinese</option>
        <option value="ko">Korean</option>
        <option value="fr">French</option>
        <option value="de">German</option>
        <option value="es">Spanish</option>
      </select>
    </div>
  </header>

  <!-- Two-column layout: input and translation result -->
  <main>
    <textarea id="input-text" placeholder="Enter text to translate..."></textarea>
    <output id="output-text"></output>
  </main>

  <!-- Modal displayed during model download -->
  <dialog id="download-dialog">
    <h3>Downloading model...</h3>
    <progress id="download-progress" max="100" value="0"></progress>
    <p id="download-status"></p>
    <button id="download-cancel">Cancel</button>
  </dialog>

  <script src="/script.js"></script>
</body>
</html>
```

Key points about the HTML.

- The favicon uses an inline SVG emoji, so no image file is needed
- `<dialog>` shows download progress. It's a standard HTML element you can display as a modal with `showModal()`
- `<output>` is for displaying translation results. It's an element that semantically represents "computed output"
- There's no translate button. Translation starts automatically when you type text (implemented in Section 5.4)

Write the CSS to `public/style.css`. We won't use any CSS framework -- just plain CSS for the layout.

```css
:root {
  --gap: 0.5rem;
  --color-border: #ccc;
  --font: system-ui, sans-serif;
}

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

html, body {
  height: 100%;
  font-family: var(--font);
}

body {
  display: flex;
  flex-direction: column;
  padding: var(--gap);
  gap: var(--gap);
}

/* Header: title + dropdowns */
header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

header div {
  display: flex;
  gap: var(--gap);
}

/* Main: two-column layout */
main {
  flex: 1;
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--gap);
  min-height: 0;
}

#input-text {
  resize: none;
  padding: 0.75rem;
  font-family: var(--font);
  font-size: 1rem;
  border: 1px solid var(--color-border);
  border-radius: 4px;
}

textarea:focus,
select:focus {
  outline: 1px solid #4a9eff;
  outline-offset: -1px;
}

#output-text {
  display: block;
  padding: 0.75rem;
  font-size: 1rem;
  border: 1px solid var(--color-border);
  border-radius: 4px;
  white-space: pre-wrap;
  overflow-y: auto;
}

/* Download modal */
dialog {
  border: 1px solid var(--color-border);
  border-radius: 8px;
  padding: 1.5rem;
  max-width: 400px;
  width: 90%;
  margin: auto;
}

dialog::backdrop {
  background: rgba(0, 0, 0, 0.4);
}

dialog h3 {
  margin-bottom: 0.75rem;
}

dialog progress {
  width: 100%;
  height: 1.25rem;
}

dialog p {
  margin-top: 0.5rem;
  text-align: center;
  color: #666;
}

dialog button {
  display: block;
  margin: 0.75rem auto 0;
  padding: 0.4rem 1.5rem;
  cursor: pointer;
}

/* Block the entire UI during translation or model switching */
body.busy {
  cursor: wait;
}

body.busy select,
body.busy textarea {
  pointer-events: none;
  opacity: 0.6;
}
```

Key points about the layout.

- `body` uses Flexbox for vertical layout, and `main` takes up the remaining height with `flex: 1`. The input and output areas extend to the bottom of the window
- `main` uses CSS Grid's `1fr 1fr` to split into two columns
- The `--gap` variable unifies all spacing. The top of the header, the space between the header and boxes, and the bottom of the boxes all have the same width
- The `body.busy` class blocks the UI during translation or model switching. JavaScript toggles it on and off

Reload the browser and you should see the input and output areas side by side. Nothing happens when you type yet, but the layout is complete.

## 5.4 Connecting the Translation Feature

Now it's time to call the server's API from JavaScript. Create `public/script.js`.

### Reading the SSE Stream

The `/translate/stream` endpoint we built in Chapter 3 is a POST endpoint. Since the browser's `EventSource` only supports GET, we'll read SSE using `fetch()` + `ReadableStream`. The basic pattern is:

1. Send a POST request with `fetch()`
2. Get a stream with `res.body.getReader()`
3. Process lines starting with `data:` as we read chunks

Chunks can be split in the middle of an SSE line, so we need to buffer them and process line by line.

### Auto-translation with Debounce

Instead of a translate button, we trigger translation automatically on text input or language change. We add a 300ms debounce to prevent requests from firing on every keystroke.

To cancel the previous translation while typing, we use `AbortController`. When new input arrives, `abort()` cancels the previous `fetch` and starts a new translation. Since we need to pass a cancellation `signal` to `fetch`, the SSE reading is written inline.

```js
const inputText = document.getElementById("input-text");
const outputText = document.getElementById("output-text");
const targetLang = document.getElementById("target-lang");

let debounceTimer = null;
let abortController = null;

async function translate() {
  const text = inputText.value.trim();
  if (!text) {
    outputText.textContent = "";
    return;
  }

  // Cancel any in-progress translation
  if (abortController) abortController.abort();
  abortController = new AbortController();
  const { signal } = abortController;

  outputText.textContent = "";
  document.body.classList.add("busy");

  try {
    const res = await fetch("/translate/stream", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, target_lang: targetLang.value }),
      signal,
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || `HTTP ${res.status}`);
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop();

      for (const line of lines) {
        if (line.startsWith("data: ")) {
          const data = line.slice(6);
          if (data === "[DONE]") return;
          const parsed = JSON.parse(data);
          if (parsed && parsed.error) {
            outputText.textContent = "Error: " + parsed.error;
            return;
          }
          outputText.textContent += parsed;
        }
      }
    }
  } catch (e) {
    if (e.name === "AbortError") return; // Cancelled by new input
    outputText.textContent = "Error: " + e.message;
  } finally {
    document.body.classList.remove("busy");
  }
}

function scheduleTranslation() {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(translate, 300);
}

inputText.addEventListener("input", scheduleTranslation);
targetLang.addEventListener("change", scheduleTranslation);
```

We use `fetch` directly because we need to pass the `AbortController`'s `signal`. Since the server can return errors as JSON objects (from the `try/catch` we added in Chapter 3), we also check for `parsed.error`.

Reload the browser and try typing some text. After 300ms, tokens should appear one by one. If you change the input, the previous translation is cancelled and a new one begins.

## 5.5 Connecting Model Selection

### Loading the Model List

When the page loads, we call `GET /models` to initialize the dropdown.

```js
const modelSelect = document.getElementById("model-select");

// Fetch model list from `GET /models` and build the dropdown
async function loadModels() {
  const res = await fetch("/models");
  const { models } = await res.json();

  modelSelect.innerHTML = ""; // Clear existing options
  for (const m of models) {
    const opt = document.createElement("option");
    opt.value = m.name;
    // Mark undownloaded models with a ⬇ icon to distinguish them
    opt.textContent = m.downloaded
      ? `${m.name} (${m.params})`
      : `${m.name} (${m.params}) ⬇`;
    opt.selected = m.selected; // Select the current model using the `selected` flag from the server
    modelSelect.appendChild(opt);
  }
}

loadModels(); // Run on page load
```

Undownloaded models are marked with a `⬇` icon to distinguish them.

### Switching Models

Changing the dropdown calls `POST /models/select`. If a download is needed, a `<dialog>` with a progress bar appears. The cancel button can abort the download.

As with translation, we use `AbortController`. Clicking the cancel button calls `abort()` to disconnect. The server detects the disconnection and aborts the download (thanks to `download_model` returning `sink.os.good()` from Chapter 4).

```js
const dialog = document.getElementById("download-dialog");
const progressBar = document.getElementById("download-progress");
const downloadStatus = document.getElementById("download-status");
const downloadCancel = document.getElementById("download-cancel");

let modelAbort = null;

downloadCancel.addEventListener("click", () => {
  if (modelAbort) modelAbort.abort();
});

modelSelect.addEventListener("change", async () => {
  const name = modelSelect.value;
  document.body.classList.add("busy");

  modelAbort = new AbortController();
  const { signal } = modelAbort;

  try {
    const res = await fetch("/models/select", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model: name }),
      signal,
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || `HTTP ${res.status}`);
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop();

      for (const line of lines) {
        if (line.startsWith("data: ")) {
          const data = line.slice(6);
          if (data === "[DONE]") return;
          const event = JSON.parse(data);

          switch (event.status) {
            case "downloading":
              if (!dialog.open) dialog.showModal(); // Show the modal
              progressBar.value = event.progress;   // Update the progress bar
              downloadStatus.textContent = `${event.progress}%`;
              break;
            case "loading":
              // Removing the `value` attribute puts `<progress>` into animated (indeterminate) state
              progressBar.removeAttribute("value");
              downloadStatus.textContent = "Loading model...";
              break;
            case "ready":
              if (dialog.open) dialog.close();
              break;
            case "error":
              if (dialog.open) dialog.close();
              alert("Download failed: " + event.message);
              break;
          }
        }
      }
    }

    await loadModels(); // Refresh the list since the `selected` flag changed
    scheduleTranslation(); // Re-translate with the new model
  } catch (e) {
    if (e.name === "AbortError") {
      // Cancelled -- revert to the original model
      await loadModels();
    } else {
      alert("Error: " + e.message);
    }
  } finally {
    document.body.classList.remove("busy");
    if (dialog.open) dialog.close();
    modelAbort = null;
  }
});
```

`progressBar.removeAttribute("value")` puts the `<progress>` element into an indeterminate (animated) state. We use this while loading the model after the download completes.

## 5.6 Complete Code

<details>
<summary data-file="index.html">Complete code (index.html)</summary>

```html
<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Translate App</title>
  <!-- Set favicon with inline SVG emoji (no image file needed) -->
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🌐</text></svg>">
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <!-- Header: title + model selector + language selector -->
  <header>
    <strong>Translate App</strong>
    <div>
      <!-- Options are dynamically populated by script.js via `GET /models` -->
      <select id="model-select" aria-label="Model"></select>
      <select id="target-lang" aria-label="Target language">
        <option value="ja">Japanese</option>
        <option value="en">English</option>
        <option value="zh">Chinese</option>
        <option value="ko">Korean</option>
        <option value="fr">French</option>
        <option value="de">German</option>
        <option value="es">Spanish</option>
      </select>
    </div>
  </header>

  <!-- Two-column layout: input and translation result -->
  <main>
    <textarea id="input-text" placeholder="Enter text to translate..."></textarea>
    <output id="output-text"></output>
  </main>

  <!-- Modal displayed during model download -->
  <dialog id="download-dialog">
    <h3>Downloading model...</h3>
    <progress id="download-progress" max="100" value="0"></progress>
    <p id="download-status"></p>
    <button id="download-cancel">Cancel</button>
  </dialog>

  <script src="/script.js"></script>
</body>
</html>
```

</details>

<details>
<summary data-file="style.css">Complete code (style.css)</summary>

```css
:root {
  --gap: 0.5rem;
  --color-border: #ccc;
  --font: system-ui, sans-serif;
}

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

html, body {
  height: 100%;
  font-family: var(--font);
}

body {
  display: flex;
  flex-direction: column;
  padding: var(--gap);
  gap: var(--gap);
}

/* Header: title + dropdowns */
header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

header div {
  display: flex;
  gap: var(--gap);
}

/* Main: two-column layout */
main {
  flex: 1;
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--gap);
  min-height: 0;
}

#input-text {
  resize: none;
  padding: 0.75rem;
  font-family: var(--font);
  font-size: 1rem;
  border: 1px solid var(--color-border);
  border-radius: 4px;
}

textarea:focus,
select:focus {
  outline: 1px solid #4a9eff;
  outline-offset: -1px;
}

#output-text {
  display: block;
  padding: 0.75rem;
  font-size: 1rem;
  border: 1px solid var(--color-border);
  border-radius: 4px;
  white-space: pre-wrap;
  overflow-y: auto;
}

/* Download modal */
dialog {
  border: 1px solid var(--color-border);
  border-radius: 8px;
  padding: 1.5rem;
  max-width: 400px;
  width: 90%;
  margin: auto;
}

dialog::backdrop {
  background: rgba(0, 0, 0, 0.4);
}

dialog h3 {
  margin-bottom: 0.75rem;
}

dialog progress {
  width: 100%;
  height: 1.25rem;
}

dialog p {
  margin-top: 0.5rem;
  text-align: center;
  color: #666;
}

dialog button {
  display: block;
  margin: 0.75rem auto 0;
  padding: 0.4rem 1.5rem;
  cursor: pointer;
}

/* Block the entire UI during translation or model switching */
body.busy {
  cursor: wait;
}

body.busy select,
body.busy textarea {
  pointer-events: none;
  opacity: 0.6;
}
```

</details>

<details>
<summary data-file="script.js">Complete code (script.js)</summary>

```js
// --- DOM Elements ---

const inputText = document.getElementById("input-text");
const outputText = document.getElementById("output-text");
const targetLang = document.getElementById("target-lang");
const modelSelect = document.getElementById("model-select");
const dialog = document.getElementById("download-dialog");
const progressBar = document.getElementById("download-progress");
const downloadStatus = document.getElementById("download-status");
const downloadCancel = document.getElementById("download-cancel");

// --- Model List ---

// Fetch model list from `GET /models` and build the dropdown
async function loadModels() {
  const res = await fetch("/models");
  const { models } = await res.json();

  modelSelect.innerHTML = ""; // Clear existing options
  for (const m of models) {
    const opt = document.createElement("option");
    opt.value = m.name;
    // Mark undownloaded models with a ⬇ icon to distinguish them
    opt.textContent = m.downloaded
      ? `${m.name} (${m.params})`
      : `${m.name} (${m.params}) ⬇`;
    opt.selected = m.selected; // Select the current model using the `selected` flag from the server
    modelSelect.appendChild(opt);
  }
}

loadModels(); // Run on page load

// --- Translation (auto-translation with debounce) ---

let debounceTimer = null;
let abortController = null;

async function translate() {
  const text = inputText.value.trim();
  if (!text) {
    outputText.textContent = "";
    return;
  }

  // Cancel any in-progress translation
  if (abortController) abortController.abort();
  abortController = new AbortController();
  const { signal } = abortController;

  outputText.textContent = "";
  document.body.classList.add("busy");

  try {
    const res = await fetch("/translate/stream", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, target_lang: targetLang.value }),
      signal,
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || `HTTP ${res.status}`);
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop();

      for (const line of lines) {
        if (line.startsWith("data: ")) {
          const data = line.slice(6);
          if (data === "[DONE]") return;
          const parsed = JSON.parse(data);
          if (parsed && parsed.error) {
            outputText.textContent = "Error: " + parsed.error;
            return;
          }
          outputText.textContent += parsed;
        }
      }
    }
  } catch (e) {
    if (e.name === "AbortError") return; // Cancelled by new input
    outputText.textContent = "Error: " + e.message;
  } finally {
    document.body.classList.remove("busy");
  }
}

function scheduleTranslation() {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(translate, 300);
}

inputText.addEventListener("input", scheduleTranslation);
targetLang.addEventListener("change", scheduleTranslation);

// --- Model Selection ---

let modelAbort = null;

downloadCancel.addEventListener("click", () => {
  if (modelAbort) modelAbort.abort();
});

modelSelect.addEventListener("change", async () => {
  const name = modelSelect.value;
  document.body.classList.add("busy");

  modelAbort = new AbortController();
  const { signal } = modelAbort;

  try {
    const res = await fetch("/models/select", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model: name }),
      signal,
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || `HTTP ${res.status}`);
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop();

      for (const line of lines) {
        if (line.startsWith("data: ")) {
          const data = line.slice(6);
          if (data === "[DONE]") return;
          const event = JSON.parse(data);

          switch (event.status) {
            case "downloading":
              if (!dialog.open) dialog.showModal();
              progressBar.value = event.progress;
              downloadStatus.textContent = `${event.progress}%`;
              break;
            case "loading":
              progressBar.removeAttribute("value");
              downloadStatus.textContent = "Loading model...";
              break;
            case "ready":
              if (dialog.open) dialog.close();
              break;
            case "error":
              if (dialog.open) dialog.close();
              alert("Download failed: " + event.message);
              break;
          }
        }
      }
    }

    await loadModels();
    scheduleTranslation(); // Re-translate with the new model
  } catch (e) {
    if (e.name === "AbortError") {
      // Cancelled -- revert to the original model
      await loadModels();
    } else {
      alert("Error: " + e.message);
    }
  } finally {
    document.body.classList.remove("busy");
    if (dialog.open) dialog.close();
    modelAbort = null;
  }
});
```

</details>

<details>
<summary data-file="main.cpp">Complete code (main.cpp)</summary>

The only server-side change is the single `set_mount_point` line. Add it before `svr.listen()` in the complete code from Chapter 4.

```cpp
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <cpp-llamalib.h>

#include <algorithm>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>

using json = nlohmann::json;

// -------------------------------------------------------------------------
// Model definitions
// -------------------------------------------------------------------------

struct ModelInfo {
  std::string name;
  std::string params;
  std::string size;
  std::string repo;
  std::string filename;
};

const std::vector<ModelInfo> MODELS = {
  {
    .name     = "gemma-2-2b-it",
    .params   = "2B",
    .size     = "1.6 GB",
    .repo     = "bartowski/gemma-2-2b-it-GGUF",
    .filename = "gemma-2-2b-it-Q4_K_M.gguf",
  },
  {
    .name     = "gemma-2-9b-it",
    .params   = "9B",
    .size     = "5.8 GB",
    .repo     = "bartowski/gemma-2-9b-it-GGUF",
    .filename = "gemma-2-9b-it-Q4_K_M.gguf",
  },
  {
    .name     = "Llama-3.1-8B-Instruct",
    .params   = "8B",
    .size     = "4.9 GB",
    .repo     = "bartowski/Meta-Llama-3.1-8B-Instruct-GGUF",
    .filename = "Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf",
  },
};

// -------------------------------------------------------------------------
// Model storage directory
// -------------------------------------------------------------------------

std::filesystem::path get_models_dir() {
#ifdef _WIN32
  auto env = std::getenv("APPDATA");
  auto base = env ? std::filesystem::path(env) : std::filesystem::path(".");
  return base / "translate-app" / "models";
#else
  auto env = std::getenv("HOME");
  auto base = env ? std::filesystem::path(env) : std::filesystem::path(".");
  return base / ".translate-app" / "models";
#endif
}

// -------------------------------------------------------------------------
// Model download
// -------------------------------------------------------------------------

// Abort the download if progress_cb returns false
bool download_model(const ModelInfo &model,
                    std::function<bool(int)> progress_cb) {
  httplib::Client cli("https://huggingface.co");
  cli.set_follow_location(true);  // Hugging Face redirects to CDN
  cli.set_read_timeout(std::chrono::hours(1)); // Long timeout for large models

  auto url = "/" + model.repo + "/resolve/main/" + model.filename;
  auto path = get_models_dir() / model.filename;
  auto tmp_path = std::filesystem::path(path).concat(".tmp");

  std::ofstream ofs(tmp_path, std::ios::binary);
  if (!ofs) { return false; }

  auto res = cli.Get(url,
    // content_receiver: receive chunks and write to file
    [&](const char *data, size_t len) {
      ofs.write(data, len);
      return ofs.good();
    },
    // progress: report download progress (return false to abort)
    [&, last_pct = -1](size_t current, size_t total) mutable {
      int pct = total ? (int)(current * 100 / total) : 0;
      if (pct == last_pct) return true; // Skip if same value
      last_pct = pct;
      return progress_cb(pct);
    });

  ofs.close();

  if (!res || res->status != 200) {
    std::filesystem::remove(tmp_path);
    return false;
  }

  // Rename after download completes
  std::filesystem::rename(tmp_path, path);
  return true;
}

// -------------------------------------------------------------------------
// Server
// -------------------------------------------------------------------------

httplib::Server svr;

void signal_handler(int sig) {
  if (sig == SIGINT || sig == SIGTERM) {
    std::cout << "\nReceived signal, shutting down gracefully...\n";
    svr.stop();
  }
}

int main() {
  // Create model storage directory
  auto models_dir = get_models_dir();
  std::filesystem::create_directories(models_dir);

  // Auto-download default model if not present
  std::string selected_model = MODELS[0].filename;
  auto path = models_dir / selected_model;
  if (!std::filesystem::exists(path)) {
    std::cout << "Downloading " << selected_model << "..." << std::endl;
    if (!download_model(MODELS[0], [](int pct) {
          std::cout << "\r" << pct << "%" << std::flush;
          return true;
        })) {
      std::cerr << "\nFailed to download model." << std::endl;
      return 1;
    }
    std::cout << std::endl;
  }
  auto llm = llamalib::Llama{path};

  // LLM inference takes time, so set a longer timeout (default is 5 seconds)
  svr.set_read_timeout(300);
  svr.set_write_timeout(300);

  svr.set_logger([](const auto &req, const auto &res) {
    std::cout << req.method << " " << req.path << " -> " << res.status
              << std::endl;
  });

  svr.Get("/health", [](const httplib::Request &, httplib::Response &res) {
    res.set_content(json{{"status", "ok"}}.dump(), "application/json");
  });

  // --- Translation endpoint (Chapter 2) ------------------------------------

  svr.Post("/translate",
           [&](const httplib::Request &req, httplib::Response &res) {
    auto input = json::parse(req.body, nullptr, false);
    if (input.is_discarded()) {
      res.status = 400;
      res.set_content(json{{"error", "Invalid JSON"}}.dump(),
                      "application/json");
      return;
    }

    if (!input.contains("text") || !input["text"].is_string() ||
        input["text"].get<std::string>().empty()) {
      res.status = 400;
      res.set_content(json{{"error", "'text' is required"}}.dump(),
                      "application/json");
      return;
    }

    auto text = input["text"].get<std::string>();
    auto target_lang = input.value("target_lang", "ja");

    auto prompt = "Translate the following text to " + target_lang +
                  ". Output only the translation, nothing else.\n\n" + text;

    try {
      auto translation = llm.chat(prompt);
      res.set_content(json{{"translation", translation}}.dump(),
                      "application/json");
    } catch (const std::exception &e) {
      res.status = 500;
      res.set_content(json{{"error", e.what()}}.dump(), "application/json");
    }
  });

  // --- SSE streaming translation (Chapter 3) --------------------------------

  svr.Post("/translate/stream",
           [&](const httplib::Request &req, httplib::Response &res) {
    auto input = json::parse(req.body, nullptr, false);
    if (input.is_discarded()) {
      res.status = 400;
      res.set_content(json{{"error", "Invalid JSON"}}.dump(),
                      "application/json");
      return;
    }

    if (!input.contains("text") || !input["text"].is_string() ||
        input["text"].get<std::string>().empty()) {
      res.status = 400;
      res.set_content(json{{"error", "'text' is required"}}.dump(),
                      "application/json");
      return;
    }

    auto text = input["text"].get<std::string>();
    auto target_lang = input.value("target_lang", "ja");

    auto prompt = "Translate the following text to " + target_lang +
                  ". Output only the translation, nothing else.\n\n" + text;

    res.set_chunked_content_provider(
        "text/event-stream",
        [&, prompt](size_t, httplib::DataSink &sink) {
          try {
            llm.chat(prompt, [&](std::string_view token) {
              sink.os << "data: "
                      << json(std::string(token)).dump(
                           -1, ' ', false, json::error_handler_t::replace)
                      << "\n\n";
              return sink.os.good(); // Abort inference on disconnect
            });
            sink.os << "data: [DONE]\n\n";
          } catch (const std::exception &e) {
            sink.os << "data: " << json({{"error", e.what()}}).dump() << "\n\n";
          }
          sink.done();
          return true;
        });
  });

  // --- Model list (Chapter 4) -----------------------------------------------

  svr.Get("/models",
          [&](const httplib::Request &, httplib::Response &res) {
    auto models_dir = get_models_dir();
    auto arr = json::array();
    for (const auto &m : MODELS) {
      auto path = models_dir / m.filename;
      arr.push_back({
        {"name",       m.name},
        {"params",     m.params},
        {"size",       m.size},
        {"downloaded", std::filesystem::exists(path)},
        {"selected",   m.filename == selected_model},
      });
    }
    res.set_content(json{{"models", arr}}.dump(), "application/json");
  });

  // --- Model selection (Chapter 4) ------------------------------------------

  svr.Post("/models/select",
           [&](const httplib::Request &req, httplib::Response &res) {
    auto input = json::parse(req.body, nullptr, false);
    if (input.is_discarded() || !input.contains("model")) {
      res.status = 400;
      res.set_content(json{{"error", "'model' is required"}}.dump(),
                      "application/json");
      return;
    }

    auto name = input["model"].get<std::string>();

    auto it = std::find_if(MODELS.begin(), MODELS.end(),
      [&](const ModelInfo &m) { return m.name == name; });

    if (it == MODELS.end()) {
      res.status = 404;
      res.set_content(json{{"error", "Unknown model"}}.dump(),
                      "application/json");
      return;
    }

    const auto &model = *it;

    // Always respond with SSE (same format whether downloaded or not)
    res.set_chunked_content_provider(
        "text/event-stream",
        [&, model](size_t, httplib::DataSink &sink) {
          // SSE event send helper
          auto send = [&](const json &event) {
            sink.os << "data: " << event.dump() << "\n\n";
          };

          // Download if not yet downloaded (report progress via SSE)
          auto path = get_models_dir() / model.filename;
          if (!std::filesystem::exists(path)) {
            bool ok = download_model(model, [&](int pct) {
              send({{"status", "downloading"}, {"progress", pct}});
              return sink.os.good(); // Abort download on client disconnect
            });
            if (!ok) {
              send({{"status", "error"}, {"message", "Download failed"}});
              sink.done();
              return true;
            }
          }

          // Load and switch to the model
          send({{"status", "loading"}});
          llm = llamalib::Llama{path};
          selected_model = model.filename;

          send({{"status", "ready"}});
          sink.done();
          return true;
        });
  });

  // --- Static file serving (Chapter 5) --------------------------------------

  svr.set_mount_point("/", "./public");

  // Allow graceful shutdown via `Ctrl+C` (`SIGINT`) or `kill` (`SIGTERM`)
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  std::cout << "Listening on http://127.0.0.1:8080" << std::endl;
  svr.listen("127.0.0.1", 8080);
}
```

</details>

## 5.7 Testing

Rebuild and start the server.

```bash
cmake --build build -j
./build/translate-server
```

Open `http://127.0.0.1:8080` in your browser.

1. Type some text -- after 300ms, tokens appear incrementally
2. Change the input -- the previous translation is cancelled and a new one starts
3. Change the language dropdown -- automatic re-translation
4. Change the model dropdown -- switches immediately if already downloaded
5. Select an undownloaded model -- a progress bar appears, and Cancel can abort it

Everything we did with curl in Chapter 4 can now be done from the browser.

## Next Chapter

The server and Web UI are complete. In the next chapter, we'll wrap this app with webview/webview to make it a desktop application that runs without a browser. We'll embed the static files into the binary so the distributable is a single executable.

**Next:** [Turning It into a Desktop App with WebView](../ch06-desktop-app)
