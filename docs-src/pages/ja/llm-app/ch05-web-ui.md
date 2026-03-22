---
title: "5. Web UIを追加する"
order: 5

---

4章までで、翻訳API・SSEストリーミング・モデル管理と、サーバーの機能は一通り揃いました。でも今のところ操作手段はcurlだけです。この章ではWeb UIを追加して、ブラウザから翻訳できるようにします。

完成するとこんな画面になります。

![Web UI](../webui.png#large-center)

- テキストを入力すると、自動でトークンが逐次表示される（debounce付き）
- ヘッダーのドロップダウンでモデルと言語を切り替えられる
- 未ダウンロードのモデルを選ぶと、進捗バー付きでダウンロードが始まる（キャンセル可能）

HTML・CSS・JavaScriptのコードは最小限です。CSSフレームワークは使わず、素のCSS（約100行）だけでレイアウトします。C++の本なので、フロントエンドの詳しい解説はしません。「こう書くとこう動く」を見せていきます。

## 5.1 ファイル構成

この章で追加するファイルです。`public/`ディレクトリにHTML・CSS・JavaScriptを置き、サーバーから配信します。

```ascii
translate-app/
├── public/
│   ├── index.html
│   ├── style.css
│   └── script.js
└── src/
    └── main.cpp      # set_mount_point を追加
```

## 5.2 静的ファイル配信を設定する

cpp-httplibの`set_mount_point`を使うと、ディレクトリをそのままHTTPで配信できます。`public/`ディレクトリを作って、空の`index.html`を置きましょう。

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

サーバーのコードに`set_mount_point`を1行追加してビルドし直します。

```cpp
// `main()`内、`svr.listen()`の前に追加
svr.set_mount_point("/", "./public");
```

サーバーを起動してブラウザで`http://127.0.0.1:8080`を開くと、「Hello!」が表示されるはずです。静的ファイルなので、`index.html`を編集したらブラウザをリロードするだけで反映されます。サーバーの再起動は不要です。

## 5.3 レイアウトを作る

`index.html`をレイアウトの完成形に書き換えます。

```html
<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Translate App</title>
  <!-- インラインSVG絵文字でfaviconを設定（画像ファイル不要） -->
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🌐</text></svg>">
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <!-- ヘッダー: タイトル + モデル選択 + 言語選択 -->
  <header>
    <strong>Translate App</strong>
    <div>
      <!-- 選択肢はscript.jsが`GET /models`で取得して動的に埋める -->
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

  <!-- 左右2カラム: 入力と翻訳結果 -->
  <main>
    <textarea id="input-text" placeholder="Enter text to translate..."></textarea>
    <output id="output-text"></output>
  </main>

  <!-- モデルダウンロード中に表示するモーダル -->
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

HTMLのポイントです。

- FaviconはインラインSVG絵文字なので、画像ファイルは不要です
- `<dialog>`はモデルダウンロード中の進捗表示に使います。HTML標準の要素で、`showModal()`でモーダルとして表示できます
- `<output>`は翻訳結果の表示用です。意味的に「計算結果の出力」を表す要素です
- 翻訳ボタンはありません。テキストを入力すると自動で翻訳が始まります（5.4節で実装）

CSSを`public/style.css`に書きます。CSSフレームワークは使わず、素のCSSだけでレイアウトします。

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

/* ヘッダー: タイトル + ドロップダウン */
header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

header div {
  display: flex;
  gap: var(--gap);
}

/* メイン: 左右2カラム */
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

/* ダウンロードモーダル */
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

/* 翻訳中・モデル切替中にUI全体をブロックする */
body.busy {
  cursor: wait;
}

body.busy select,
body.busy textarea {
  pointer-events: none;
  opacity: 0.6;
}
```

レイアウトのポイントです。

- `body`をFlexboxで縦並びにし、`main`が`flex: 1`で残りの高さを占めます。入力欄と出力欄がウィンドウ下端まで伸びます
- `main`はCSS Gridの`1fr 1fr`で左右2カラムに分割しています
- `--gap`変数で全てのスペーシングを統一しています。ヘッダー上端、ヘッダーとBox間、Box下端が全て同じ幅です
- `body.busy`クラスは、翻訳中やモデル切り替え中にUIをブロックするために使います。JavaScriptから付け外しします

ブラウザをリロードすると、入力欄と出力欄が横に並んだ画面が表示されるはずです。まだ何も入力しても何も起きませんが、レイアウトは完成です。

## 5.4 翻訳機能をつなぐ

いよいよJavaScriptでサーバーのAPIを呼び出します。`public/script.js`を作ります。

### SSEストリームの読み方

3章で作った`/translate/stream`はPOSTエンドポイントです。ブラウザの`EventSource`はGETしか使えないので、`fetch()` + `ReadableStream`でSSEを読みます。基本パターンはこうです。

1. `fetch()`でPOSTリクエストを送る
2. `res.body.getReader()`でストリームを取得
3. チャンクを読みながら`data:`で始まる行を処理する

チャンクはSSEの行の途中で切れることがあるので、バッファに溜めて行単位で処理する必要があります。

### debounce付き自動翻訳

翻訳ボタンの代わりに、テキスト入力や言語変更をトリガーにして自動で翻訳を開始します。300msのdebounceを入れて、タイピング中に毎回リクエストが飛ばないようにします。

入力中に前の翻訳を中断するため、`AbortController`を使います。新しい入力があると`abort()`で前の`fetch`をキャンセルし、新しい翻訳を開始します。`fetch`にキャンセル用の`signal`を渡す必要があるので、SSEの読み取りはインラインで書いています。

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

  // 進行中の翻訳があればキャンセル
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
    if (e.name === "AbortError") return; // 新しい入力でキャンセルされた
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

`AbortController`の`signal`を渡す必要があるため、`fetch`を直接使っています。サーバーからエラーがJSONオブジェクトで返ってくることがあるので（3章で追加した`try/catch`）、`parsed.error`のチェックも入れています。

ブラウザをリロードして、テキストを入力してみましょう。300ms後にトークンが1つずつ表示されるはずです。入力を変えると前の翻訳が中断され、新しい翻訳が始まります。

## 5.5 モデル選択をつなぐ

### モデル一覧の読み込み

ページを開いた時に`GET /models`を呼んで、ドロップダウンを初期化します。

```js
const modelSelect = document.getElementById("model-select");

// `GET /models`からモデル一覧を取得し、ドロップダウンを構築する
async function loadModels() {
  const res = await fetch("/models");
  const { models } = await res.json();

  modelSelect.innerHTML = ""; // 既存の選択肢をクリア
  for (const m of models) {
    const opt = document.createElement("option");
    opt.value = m.name;
    // 未ダウンロードのモデルには ⬇ マークを付けて区別する
    opt.textContent = m.downloaded
      ? `${m.name} (${m.params})`
      : `${m.name} (${m.params}) ⬇`;
    opt.selected = m.selected; // サーバーが返す`selected`フラグで現在のモデルを選択状態に
    modelSelect.appendChild(opt);
  }
}

loadModels(); // ページ読み込み時に実行
```

未ダウンロードのモデルには`⬇`マークを付けて区別します。

### モデルの切り替え

ドロップダウンを変更すると`POST /models/select`を呼びます。ダウンロードが必要な場合は`<dialog>`で進捗バーを表示します。キャンセルボタンで中断もできます。

翻訳と同様に`AbortController`を使います。キャンセルボタンが押されたら`abort()`で接続を切断します。サーバー側は切断を検知してダウンロードを中断します（4章の`download_model`で`sink.os.good()`を返しているおかげです）。

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
              if (!dialog.open) dialog.showModal(); // モーダルを表示
              progressBar.value = event.progress;   // 進捗バーを更新
              downloadStatus.textContent = `${event.progress}%`;
              break;
            case "loading":
              // `value`属性を消すと`<progress>`がアニメーション（不確定）状態になる
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

    await loadModels(); // `selected`フラグが変わったので一覧を再取得
    scheduleTranslation(); // 新しいモデルで再翻訳
  } catch (e) {
    if (e.name === "AbortError") {
      // キャンセルされた — 元のモデルに戻す
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

`progressBar.removeAttribute("value")`で`<progress>`をindeterminate（アニメーション）状態にしています。ダウンロード完了後のモデルロード中に使います。

## 5.6 全体のコード

<details>
<summary data-file="index.html">全体のコード（index.html）</summary>

```html
<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Translate App</title>
  <!-- インラインSVG絵文字でfaviconを設定（画像ファイル不要） -->
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🌐</text></svg>">
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <!-- ヘッダー: タイトル + モデル選択 + 言語選択 -->
  <header>
    <strong>Translate App</strong>
    <div>
      <!-- 選択肢はscript.jsが`GET /models`で取得して動的に埋める -->
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

  <!-- 左右2カラム: 入力と翻訳結果 -->
  <main>
    <textarea id="input-text" placeholder="Enter text to translate..."></textarea>
    <output id="output-text"></output>
  </main>

  <!-- モデルダウンロード中に表示するモーダル -->
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
<summary data-file="style.css">全体のコード（style.css）</summary>

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

/* ヘッダー: タイトル + ドロップダウン */
header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

header div {
  display: flex;
  gap: var(--gap);
}

/* メイン: 左右2カラム */
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

/* ダウンロードモーダル */
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

/* 翻訳中・モデル切替中にUI全体をブロックする */
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
<summary data-file="script.js">全体のコード（script.js）</summary>

```js
// --- DOM要素 ---

const inputText = document.getElementById("input-text");
const outputText = document.getElementById("output-text");
const targetLang = document.getElementById("target-lang");
const modelSelect = document.getElementById("model-select");
const dialog = document.getElementById("download-dialog");
const progressBar = document.getElementById("download-progress");
const downloadStatus = document.getElementById("download-status");
const downloadCancel = document.getElementById("download-cancel");

// --- モデル一覧 ---

// `GET /models`からモデル一覧を取得し、ドロップダウンを構築する
async function loadModels() {
  const res = await fetch("/models");
  const { models } = await res.json();

  modelSelect.innerHTML = ""; // 既存の選択肢をクリア
  for (const m of models) {
    const opt = document.createElement("option");
    opt.value = m.name;
    // 未ダウンロードのモデルには ⬇ マークを付けて区別する
    opt.textContent = m.downloaded
      ? `${m.name} (${m.params})`
      : `${m.name} (${m.params}) ⬇`;
    opt.selected = m.selected; // サーバーが返す`selected`フラグで現在のモデルを選択状態に
    modelSelect.appendChild(opt);
  }
}

loadModels(); // ページ読み込み時に実行

// --- 翻訳（debounce付き自動翻訳） ---

let debounceTimer = null;
let abortController = null;

async function translate() {
  const text = inputText.value.trim();
  if (!text) {
    outputText.textContent = "";
    return;
  }

  // 進行中の翻訳があればキャンセル
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
    if (e.name === "AbortError") return; // 新しい入力でキャンセルされた
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

// --- モデル選択 ---

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
    scheduleTranslation(); // 新しいモデルで再翻訳
  } catch (e) {
    if (e.name === "AbortError") {
      // キャンセルされた — 元のモデルに戻す
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
<summary data-file="main.cpp">全体のコード（main.cpp）</summary>

サーバー側の変更は`set_mount_point`の1行だけです。4章の全体コードの`svr.listen()`の前に追加してください。

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
// モデル定義
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
// モデル保存ディレクトリ
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
// モデルダウンロード
// -------------------------------------------------------------------------

// progress_cbがfalseを返したらダウンロードを中断する
bool download_model(const ModelInfo &model,
                    std::function<bool(int)> progress_cb) {
  httplib::Client cli("https://huggingface.co");
  cli.set_follow_location(true);  // Hugging FaceはCDNにリダイレクトする
  cli.set_read_timeout(std::chrono::hours(1)); // 大きなモデルに備えて長めに

  auto url = "/" + model.repo + "/resolve/main/" + model.filename;
  auto path = get_models_dir() / model.filename;
  auto tmp_path = std::filesystem::path(path).concat(".tmp");

  std::ofstream ofs(tmp_path, std::ios::binary);
  if (!ofs) { return false; }

  auto res = cli.Get(url,
    // content_receiver: チャンクごとにデータを受け取ってファイルに書き込む
    [&](const char *data, size_t len) {
      ofs.write(data, len);
      return ofs.good();
    },
    // progress: ダウンロード進捗を通知（falseを返すと中断）
    [&, last_pct = -1](size_t current, size_t total) mutable {
      int pct = total ? (int)(current * 100 / total) : 0;
      if (pct == last_pct) return true; // 同じ値なら通知をスキップ
      last_pct = pct;
      return progress_cb(pct);
    });

  ofs.close();

  if (!res || res->status != 200) {
    std::filesystem::remove(tmp_path);
    return false;
  }

  // ダウンロード完了後にリネーム
  std::filesystem::rename(tmp_path, path);
  return true;
}

// -------------------------------------------------------------------------
// サーバー
// -------------------------------------------------------------------------

httplib::Server svr;

void signal_handler(int sig) {
  if (sig == SIGINT || sig == SIGTERM) {
    std::cout << "\nReceived signal, shutting down gracefully...\n";
    svr.stop();
  }
}

int main() {
  // モデル保存ディレクトリを作成
  auto models_dir = get_models_dir();
  std::filesystem::create_directories(models_dir);

  // デフォルトモデルが未ダウンロードなら自動取得
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

  // LLM推論は時間がかかるのでタイムアウトを長めに設定（デフォルトは5秒）
  svr.set_read_timeout(300);
  svr.set_write_timeout(300);

  svr.set_logger([](const auto &req, const auto &res) {
    std::cout << req.method << " " << req.path << " -> " << res.status
              << std::endl;
  });

  svr.Get("/health", [](const httplib::Request &, httplib::Response &res) {
    res.set_content(json{{"status", "ok"}}.dump(), "application/json");
  });

  // --- 翻訳エンドポイント（2章） -----------------------------------------

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

  // --- SSEストリーミング翻訳（3章）--------------------------------------

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
              return sink.os.good(); // 切断されたら推論を中断
            });
            sink.os << "data: [DONE]\n\n";
          } catch (const std::exception &e) {
            sink.os << "data: " << json({{"error", e.what()}}).dump() << "\n\n";
          }
          sink.done();
          return true;
        });
  });

  // --- モデル一覧（4章） -------------------------------------------------

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

  // --- モデル選択（4章） -------------------------------------------------

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

    // 常にSSEで応答する（DL済みでも未DLでも同じ形式）
    res.set_chunked_content_provider(
        "text/event-stream",
        [&, model](size_t, httplib::DataSink &sink) {
          // SSEイベント送信ヘルパー
          auto send = [&](const json &event) {
            sink.os << "data: " << event.dump() << "\n\n";
          };

          // 未ダウンロードならダウンロード（進捗をSSEで通知）
          auto path = get_models_dir() / model.filename;
          if (!std::filesystem::exists(path)) {
            bool ok = download_model(model, [&](int pct) {
              send({{"status", "downloading"}, {"progress", pct}});
              return sink.os.good(); // クライアント切断時にダウンロードを中断
            });
            if (!ok) {
              send({{"status", "error"}, {"message", "Download failed"}});
              sink.done();
              return true;
            }
          }

          // モデルをロードして切り替え
          send({{"status", "loading"}});
          llm = llamalib::Llama{path};
          selected_model = model.filename;

          send({{"status", "ready"}});
          sink.done();
          return true;
        });
  });

  // --- 静的ファイル配信（5章） -------------------------------------------

  svr.set_mount_point("/", "./public");

  // `Ctrl+C` (`SIGINT`)や`kill` (`SIGTERM`)でサーバーを停止できるようにする
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  std::cout << "Listening on http://127.0.0.1:8080" << std::endl;
  svr.listen("127.0.0.1", 8080);
}
```

</details>

## 5.7 動作確認

ビルドし直してサーバーを起動します。

```bash
cmake --build build -j
./build/translate-server
```

ブラウザで`http://127.0.0.1:8080`を開きます。

1. テキストを入力する → 300ms後にトークンが逐次表示される
2. 入力を変更する → 前の翻訳が中断され、新しい翻訳が始まる
3. 言語のドロップダウンを変更する → 自動で再翻訳される
4. モデルのドロップダウンを変更する → ダウンロード済みならすぐ切り替わる
5. 未ダウンロードのモデルを選ぶ → 進捗バーが表示され、Cancelで中断できる

curlで操作していた4章と同じことが、ブラウザからできるようになりました。

## 次の章へ

サーバーとWeb UIが揃いました。次の章ではこのアプリをwebview/webviewで包んで、ブラウザなしで動くデスクトップアプリにします。静的ファイルをバイナリに埋め込んで、配布物をバイナリ1つにまとめます。

**Next:** [WebViewでデスクトップアプリ化する](../ch06-desktop-app)
