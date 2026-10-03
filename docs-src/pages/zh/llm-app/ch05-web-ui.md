---
title: "5. 添加 Web UI"
order: 5

---

到第 4 章结束时，我们已经把服务器的功能都构建完毕了：翻译 API、SSE 流式传输以及模型管理。但到目前为止，与它交互的唯一方式还是通过 curl。在本章中，我们将添加一个 Web UI，这样你就可以在浏览器中翻译了。

完成后的界面如下所示。

![Web UI](../webui.png#large-center)

- 当你输入文本时，token 会逐个出现（带有防抖）
- 你可以通过页头的下拉菜单切换模型和语言
- 选择尚未下载的模型会启动下载，并显示进度条（可取消）

HTML、CSS 和 JavaScript 代码都很精简。我们不会使用任何 CSS 框架 —— 只用纯 CSS（约 100 行）来完成布局。由于这是一本 C++ 书籍，我们不会深入讲解前端的细节。我们只会告诉你“这样写，就会得到那样的效果”。

## 5.1 文件结构

这些是我们在本章中要添加的文件。我们会把 HTML、CSS 和 JavaScript 放在 `public/` 目录中，并由服务器提供这些文件。

```ascii
translate-app/
├── public/
│   ├── index.html
│   ├── style.css
│   └── script.js
└── src/
    └── main.cpp      # 添加 set_mount_point
```

## 5.2 搭建静态文件服务

使用 cpp-httplib 的 `set_mount_point`，你可以直接通过 HTTP 提供某个目录。创建 `public/` 目录，并在其中放置一个空的 `index.html`。

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

在服务器代码中添加一行 `set_mount_point`，然后重新构建。

```cpp
// 添加在 `main()` 内部、`svr.listen()` 之前
svr.set_mount_point("/", "./public");
```

启动服务器，并在浏览器中打开 `http://127.0.0.1:8080` —— 你应该会看到显示 “Hello!”。由于这些是静态文件，编辑 `index.html` 后只需重新加载浏览器即可看到变化，无需重启服务器。

## 5.3 构建布局

用最终的布局替换 `index.html`。

```html
<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Translate App</title>
  <!-- 使用内联 SVG emoji 设置 favicon（无需图片文件） -->
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🌐</text></svg>">
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <!-- 页头：标题 + 模型选择器 + 语言选择器 -->
  <header>
    <strong>Translate App</strong>
    <div>
      <!-- 选项由 script.js 通过 `GET /models` 动态填充 -->
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

  <!-- 双栏布局：输入与翻译结果 -->
  <main>
    <textarea id="input-text" placeholder="Enter text to translate..."></textarea>
    <output id="output-text"></output>
  </main>

  <!-- 模型下载期间显示的模态框 -->
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

关于 HTML 的要点。

- favicon 使用内联 SVG emoji，因此无需图片文件
- `<dialog>` 用于显示下载进度。它是一个标准的 HTML 元素，可以通过 `showModal()` 以模态框形式显示
- `<output>` 用于显示翻译结果。它是一个在语义上表示“计算输出”的元素
- 没有翻译按钮。输入文本时会自动开始翻译（在第 5.4 节实现）

将 CSS 写入 `public/style.css`。我们不会使用任何 CSS 框架 —— 只用纯 CSS 来完成布局。

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

/* 页头：标题 + 下拉菜单 */
header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

header div {
  display: flex;
  gap: var(--gap);
}

/* 主区域：双栏布局 */
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

/* 下载模态框 */
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

/* 在翻译或切换模型期间阻塞整个 UI */
body.busy {
  cursor: wait;
}

body.busy select,
body.busy textarea {
  pointer-events: none;
  opacity: 0.6;
}
```

关于布局的要点。

- `body` 使用 Flexbox 进行垂直布局，`main` 通过 `flex: 1` 占据剩余高度。输入和输出区域会一直延伸到窗口底部
- `main` 使用 CSS Grid 的 `1fr 1fr` 分为两栏
- `--gap` 变量统一了所有间距。页头顶部、页头与输入框之间的间距以及输入框底部都具有相同的宽度
- `body.busy` 类在翻译或切换模型期间阻塞 UI。JavaScript 会切换它的开与关

重新加载浏览器，你应该会看到输入和输出区域并排显示。此时输入还不会有任何反应，但布局已经完成。

## 5.4 接入翻译功能

现在轮到从 JavaScript 调用服务器的 API 了。创建 `public/script.js`。

### 读取 SSE 流

我们在第 3 章构建的 `/translate/stream` 端点是一个 POST 端点。由于浏览器的 `EventSource` 只支持 GET，我们将使用 `fetch()` + `ReadableStream` 来读取 SSE。基本模式如下：

1. 使用 `fetch()` 发送 POST 请求
2. 使用 `res.body.getReader()` 获取流
3. 在读取数据块时，处理以 `data:` 开头的行

数据块可能会在 SSE 行的中间被拆分，因此我们需要对它们进行缓冲，并逐行处理。

### 带防抖的自动翻译

我们没有使用翻译按钮，而是在文本输入或语言变更时自动触发翻译。我们添加了 300ms 的防抖，以避免每次按键都触发请求。

为了在输入过程中取消上一次翻译，我们使用 `AbortController`。当有新输入到来时，`abort()` 会取消上一次 `fetch` 并开始新的翻译。由于需要向 `fetch` 传入用于取消的 `signal`，SSE 的读取逻辑就内联写在了一起。

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

  // 取消任何进行中的翻译
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
    if (e.name === "AbortError") return; // 被新输入取消
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

我们直接使用 `fetch`，因为需要传入 `AbortController` 的 `signal`。由于服务器可能会以 JSON 对象的形式返回错误（来自我们在第 3 章添加的 `try/catch`），我们还会检查 `parsed.error`。

重新加载浏览器并尝试输入一些文本。300ms 后，token 应该会逐个出现。如果你修改输入，上一次翻译会被取消，并开始新的翻译。

## 5.5 接入模型选择

### 加载模型列表

页面加载时，我们调用 `GET /models` 来初始化下拉菜单。

```js
const modelSelect = document.getElementById("model-select");

// 从 `GET /models` 获取模型列表并构建下拉菜单
async function loadModels() {
  const res = await fetch("/models");
  const { models } = await res.json();

  modelSelect.innerHTML = ""; // 清除现有选项
  for (const m of models) {
    const opt = document.createElement("option");
    opt.value = m.name;
    // 用 ⬇ 图标标记尚未下载的模型，以作区分
    opt.textContent = m.downloaded
      ? `${m.name} (${m.params})`
      : `${m.name} (${m.params}) ⬇`;
    opt.selected = m.selected; // 使用服务器返回的 `selected` 标志选中当前模型
    modelSelect.appendChild(opt);
  }
}

loadModels(); // 在页面加载时运行
```

尚未下载的模型会用 `⬇` 图标标记，以便区分。

### 切换模型

更改下拉菜单会调用 `POST /models/select`。如果需要下载，会弹出一个带进度条的 `<dialog>`。取消按钮可以中止下载。

与翻译一样，我们使用 `AbortController`。点击取消按钮会调用 `abort()` 来断开连接。服务器检测到断开后会中止下载（这要归功于第 4 章中 `download_model` 返回的 `sink.os.good()`）。

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
              if (!dialog.open) dialog.showModal(); // 显示模态框
              progressBar.value = event.progress;   // 更新进度条
              downloadStatus.textContent = `${event.progress}%`;
              break;
            case "loading":
              // 移除 `value` 属性会让 `<progress>` 进入动画（不确定）状态
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

    await loadModels(); // 由于 `selected` 标志已变化，刷新列表
    scheduleTranslation(); // 使用新模型重新翻译
  } catch (e) {
    if (e.name === "AbortError") {
      // 已取消 —— 恢复为原始模型
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

`progressBar.removeAttribute("value")` 会让 `<progress>` 元素进入不确定（动画）状态。我们在下载完成后加载模型期间使用它。

## 5.6 完整代码

<details>
<summary data-file="index.html">完整代码（index.html）</summary>

```html
<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Translate App</title>
  <!-- 使用内联 SVG emoji 设置 favicon（无需图片文件） -->
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🌐</text></svg>">
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <!-- 页头：标题 + 模型选择器 + 语言选择器 -->
  <header>
    <strong>Translate App</strong>
    <div>
      <!-- 选项由 script.js 通过 `GET /models` 动态填充 -->
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

  <!-- 双栏布局：输入与翻译结果 -->
  <main>
    <textarea id="input-text" placeholder="Enter text to translate..."></textarea>
    <output id="output-text"></output>
  </main>

  <!-- 模型下载期间显示的模态框 -->
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
<summary data-file="style.css">完整代码（style.css）</summary>

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

/* 页头：标题 + 下拉菜单 */
header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

header div {
  display: flex;
  gap: var(--gap);
}

/* 主区域：双栏布局 */
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

/* 下载模态框 */
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

/* 在翻译或切换模型期间阻塞整个 UI */
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
<summary data-file="script.js">完整代码（script.js）</summary>

```js
// --- DOM 元素 ---

const inputText = document.getElementById("input-text");
const outputText = document.getElementById("output-text");
const targetLang = document.getElementById("target-lang");
const modelSelect = document.getElementById("model-select");
const dialog = document.getElementById("download-dialog");
const progressBar = document.getElementById("download-progress");
const downloadStatus = document.getElementById("download-status");
const downloadCancel = document.getElementById("download-cancel");

// --- 模型列表 ---

// 从 `GET /models` 获取模型列表并构建下拉菜单
async function loadModels() {
  const res = await fetch("/models");
  const { models } = await res.json();

  modelSelect.innerHTML = ""; // 清除现有选项
  for (const m of models) {
    const opt = document.createElement("option");
    opt.value = m.name;
    // 用 ⬇ 图标标记尚未下载的模型，以作区分
    opt.textContent = m.downloaded
      ? `${m.name} (${m.params})`
      : `${m.name} (${m.params}) ⬇`;
    opt.selected = m.selected; // 使用服务器返回的 `selected` 标志选中当前模型
    modelSelect.appendChild(opt);
  }
}

loadModels(); // 在页面加载时运行

// --- 翻译（带防抖的自动翻译） ---

let debounceTimer = null;
let abortController = null;

async function translate() {
  const text = inputText.value.trim();
  if (!text) {
    outputText.textContent = "";
    return;
  }

  // 取消任何进行中的翻译
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
    if (e.name === "AbortError") return; // 被新输入取消
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

// --- 模型选择 ---

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
    scheduleTranslation(); // 使用新模型重新翻译
  } catch (e) {
    if (e.name === "AbortError") {
      // 已取消 —— 恢复为原始模型
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
<summary data-file="main.cpp">完整代码（main.cpp）</summary>

服务器端唯一的改动就是那一行 `set_mount_point`。在第 4 章的完整代码中，把它添加到 `svr.listen()` 之前。

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
// 模型定义
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
// 模型存储目录
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
// 模型下载
// -------------------------------------------------------------------------

// 如果 progress_cb 返回 false，则中止下载
bool download_model(const ModelInfo &model,
                    std::function<bool(int)> progress_cb) {
  httplib::Client cli("https://huggingface.co");
  cli.set_follow_location(true);  // Hugging Face 会重定向到 CDN
  cli.set_read_timeout(std::chrono::hours(1)); // 为大模型设置较长的超时时间

  auto url = "/" + model.repo + "/resolve/main/" + model.filename;
  auto path = get_models_dir() / model.filename;
  auto tmp_path = std::filesystem::path(path).concat(".tmp");

  std::ofstream ofs(tmp_path, std::ios::binary);
  if (!ofs) { return false; }

  auto res = cli.Get(url,
    // content_receiver：接收数据块并写入文件
    [&](const char *data, size_t len) {
      ofs.write(data, len);
      return ofs.good();
    },
    // progress：报告下载进度（返回 false 以中止）
    [&, last_pct = -1](size_t current, size_t total) mutable {
      int pct = total ? (int)(current * 100 / total) : 0;
      if (pct == last_pct) return true; // 如果值相同则跳过
      last_pct = pct;
      return progress_cb(pct);
    });

  ofs.close();

  if (!res || res->status != 200) {
    std::filesystem::remove(tmp_path);
    return false;
  }

  // 下载完成后重命名
  std::filesystem::rename(tmp_path, path);
  return true;
}

// -------------------------------------------------------------------------
// 服务器
// -------------------------------------------------------------------------

httplib::Server svr;

void signal_handler(int sig) {
  if (sig == SIGINT || sig == SIGTERM) {
    std::cout << "\nReceived signal, shutting down gracefully...\n";
    svr.stop();
  }
}

int main() {
  // 创建模型存储目录
  auto models_dir = get_models_dir();
  std::filesystem::create_directories(models_dir);

  // 如果默认模型不存在则自动下载
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

  // LLM 推理需要时间，因此设置较长的超时时间（默认为 5 秒）
  svr.set_read_timeout(300);
  svr.set_write_timeout(300);

  svr.set_logger([](const auto &req, const auto &res) {
    std::cout << req.method << " " << req.path << " -> " << res.status
              << std::endl;
  });

  svr.Get("/health", [](const httplib::Request &, httplib::Response &res) {
    res.set_content(json{{"status", "ok"}}.dump(), "application/json");
  });

  // --- 翻译端点（第 2 章） ------------------------------------

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

  // --- SSE 流式翻译（第 3 章） --------------------------------

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
              return sink.os.good(); // 客户端断开时中止推理
            });
            sink.os << "data: [DONE]\n\n";
          } catch (const std::exception &e) {
            sink.os << "data: " << json({{"error", e.what()}}).dump() << "\n\n";
          }
          sink.done();
          return true;
        });
  });

  // --- 模型列表（第 4 章） -----------------------------------------------

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

  // --- 模型选择（第 4 章） ------------------------------------------

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

    // 始终以 SSE 响应（无论是否已下载都使用相同格式）
    res.set_chunked_content_provider(
        "text/event-stream",
        [&, model](size_t, httplib::DataSink &sink) {
          // SSE 事件发送辅助函数
          auto send = [&](const json &event) {
            sink.os << "data: " << event.dump() << "\n\n";
          };

          // 如果尚未下载则下载（通过 SSE 报告进度）
          auto path = get_models_dir() / model.filename;
          if (!std::filesystem::exists(path)) {
            bool ok = download_model(model, [&](int pct) {
              send({{"status", "downloading"}, {"progress", pct}});
              return sink.os.good(); // 客户端断开时中止下载
            });
            if (!ok) {
              send({{"status", "error"}, {"message", "Download failed"}});
              sink.done();
              return true;
            }
          }

          // 加载并切换到该模型
          send({{"status", "loading"}});
          llm = llamalib::Llama{path};
          selected_model = model.filename;

          send({{"status", "ready"}});
          sink.done();
          return true;
        });
  });

  // --- 静态文件服务（第 5 章） --------------------------------------

  svr.set_mount_point("/", "./public");

  // 允许通过 `Ctrl+C`（`SIGINT`）或 `kill`（`SIGTERM`）进行优雅关闭
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  std::cout << "Listening on http://127.0.0.1:8080" << std::endl;
  svr.listen("127.0.0.1", 8080);
}
```

</details>

## 5.7 测试

重新构建并启动服务器。

```bash
cmake --build build -j
./build/translate-server
```

在浏览器中打开 `http://127.0.0.1:8080`。

1. 输入一些文本 —— 300ms 后，token 会增量出现
2. 修改输入 —— 上一次翻译被取消，并开始新的翻译
3. 更改语言下拉菜单 —— 自动重新翻译
4. 更改模型下拉菜单 —— 如果已下载则立即切换
5. 选择一个尚未下载的模型 —— 出现进度条，点击 Cancel 可以中止

我们在第 4 章用 curl 做的所有事情，现在都可以从浏览器中完成了。

## 下一章

服务器和 Web UI 都已完成。在下一章中，我们将用 webview/webview 把这个应用包装起来，使它成为一个无需浏览器即可运行的桌面应用。我们会把静态文件嵌入到二进制文件中，这样发布产物就是一个单独的可执行文件。

**下一章：** [使用 WebView 将其变成桌面应用](../ch06-desktop-app)
