---
title: "8. 自分だけのアプリにカスタマイズする"
order: 8

---

7章までで翻訳デスクトップアプリが完成し、プロダクション品質のコードとの違いも学びました。この章では、ここまで作ったアプリを**自分だけのアプリに作り変える**ためのポイントをまとめます。

翻訳アプリはあくまで題材です。llama.cppを自分のライブラリに差し替えれば、同じ構成でどんなアプリでも作れます。

## 8.1 ビルド設定を差し替える

まず`CMakeLists.txt`で、llama.cpp関連の`FetchContent`を自分のライブラリに置き換えます。

```cmake
# 削除: llama.cpp と cpp-llamalib の FetchContent

# 追加: 自分のライブラリ
FetchContent_Declare(my_lib
    GIT_REPOSITORY https://github.com/yourname/my-lib
    GIT_TAG        main
)
FetchContent_MakeAvailable(my_lib)

target_link_libraries(my-app PRIVATE
    httplib::httplib
    nlohmann_json::nlohmann_json
    my_lib        # cpp-llamalib の代わりに自分のライブラリ
    # ...
)
```

ライブラリがCMakeに対応していない場合は、ヘッダーファイルとソースファイルを直接`src/`に置いて`add_executable`に追加すればOKです。cpp-httplibやnlohmann/json、webviewはそのまま残します。

## 8.2 APIを自分のタスクに合わせる

翻訳APIのエンドポイントとパラメータを、自分のタスクに合わせて変更します。

| 翻訳アプリ | 自分のアプリ（例: 画像処理） |
|---|---|
| `POST /translate` | `POST /process` |
| `{"text": "...", "target_lang": "ja"}` | `{"image": "base64...", "filter": "blur"}` |
| `POST /translate/stream` | `POST /process/stream` |
| `GET /models` | `GET /filters`や`GET /presets` |

個々のハンドラの中身も書き換えます。例えば`llm.chat()`を呼んでいた箇所を、自分のライブラリのAPIに差し替えるだけです。

```cpp
// Before: LLM翻訳
auto translation = llm.chat(prompt);
res.set_content(json{{"translation", translation}}.dump(), "application/json");

// After: 例えば画像処理ライブラリの場合
auto result = my_lib::process(input_image, options);
res.set_content(json{{"result", result}}.dump(), "application/json");
```

SSEストリーミングも同じです。コールバックで進捗を返す関数があれば、3章と同じパターンで逐次レスポンスを返せます。LLMに限らず、処理に時間がかかるタスクならどれでも使えます。画像処理の進捗、データ変換のステップ、長時間の計算結果など、用途は様々です。

## 8.3 設計上の注意点

### 初期化コストが高いライブラリ

本書ではLLMモデルを`main()`の先頭でロードし、変数に保持しています。これは意図的な設計です。リクエストのたびにモデルをロードすると数秒かかるので、起動時に1回だけロードして使い回しています。大きなデータファイルの読み込みやGPUリソースの確保など、初期化が重いライブラリでも同じアプローチが使えます。

### スレッド安全性

cpp-httplibはスレッドプールでリクエストを並行処理します。4章ではモデル切り替え時に`llm`オブジェクトが上書きされる問題を`std::mutex`で保護しました。自分のライブラリを組み込む場合も同じパターンが使えます。ライブラリがスレッドセーフでない場合や、オブジェクトの差し替えが発生する場合は`std::mutex`で保護してください。

## 8.4 UIをカスタマイズする

`public/`の3ファイルを編集します。

- **`index.html`** — 入力フォームの構成を変えます。`<textarea>`を`<input type="file">`にしたり、パラメータの入力欄を追加したり
- **`style.css`** — レイアウトやカラーを変更します。2カラムのままでも、1カラムに変えても
- **`script.js`** — `fetch()`の送信先URLとリクエストボディ、レスポンスの表示方法を書き換えます

サーバー側のコードは変えなくても、HTMLを差し替えるだけで全く別のアプリに見えます。静的ファイルなのでサーバーの再起動なしにブラウザをリロードするだけで確認でき、試行錯誤しやすいです。

本書では素のHTML・CSS・JavaScriptで書きましたが、VueやReactなどのフロントエンドフレームワークやCSSフレームワークを組み合わせれば、さらに使い勝手の良いアプリに仕上げることができます。

## 8.5 配布するときの注意点

### ライセンス

使っているライブラリのライセンスを確認してください。cpp-httplib（MIT）、nlohmann/json（MIT）、webview（MIT）はいずれも商用利用可能です。自分のライブラリや、それが依存するライブラリのライセンスも忘れずに確認しましょう。

### モデルやデータファイル

4章で作ったダウンロード機能は、LLMモデルに限らず使えます。大きなデータファイルが必要なアプリなら、同じパターンで初回起動時に自動ダウンロードさせると、バイナリサイズを抑えつつユーザーの手間を省けます。

データが小さければ、cpp-embedlibでバイナリに埋め込んでしまうのも手です。

### クロスプラットフォームビルド

webviewはmacOS・Linux・Windowsに対応しています。各プラットフォーム向けにビルドする場合:

- **macOS** — 追加の依存なし
- **Linux** — `libwebkit2gtk-4.1-dev`が必要
- **Windows** — WebView2ランタイムが必要（Windows 11は標準搭載）

CI（GitHub Actionsなど）でクロスプラットフォームビルドを自動化するのもおすすめです。

## おわりに

最後まで読んでくださり、ありがとうございます。🙏

この本は、1章の`/health`が`{"status":"ok"}`を返すところから始まりました。そこからREST API、SSEストリーミング、Hugging Faceからのモデルダウンロード、ブラウザで動くWeb UI、そしてシングルバイナリのデスクトップアプリへ。7章では`llama-server`のコードを読んで、プロダクション品質のサーバーとの設計の違いを学びました。長い道のりでしたが、ここまで付き合ってくださったことに心から感謝します。

振り返ると、cpp-httplibのいくつかの主要な機能を実際に使いました。

- **サーバー**: ルーティング、JSONレスポンス、`set_chunked_content_provider`によるSSEストリーミング、`set_mount_point`による静的ファイル配信
- **クライアント**: HTTPS接続、リダイレクト追従、コンテンツレシーバーによる大容量ダウンロード、進捗コールバック
- **WebView連携**: `bind_to_any_port` + `listen_after_bind`でバックグラウンドスレッド化

cpp-httplibにはこの他にも、マルチパートによるファイルアップロード、認証、タイムアウト制御、圧縮、レンジリクエストなど便利な機能があります。詳しくは [A Tour of cpp-httplib](../../tour/) をご覧ください。

これらのパターンは翻訳アプリに限りません。自分のC++ライブラリにWeb APIを付けたい、ブラウザUIで操作できるようにしたい、配布しやすいデスクトップアプリにしたい―そんなときに、この本がリファレンスになれば嬉しいです。

あなたのライブラリで、あなただけのアプリを作ってみてください。Happy hacking! 🚀
