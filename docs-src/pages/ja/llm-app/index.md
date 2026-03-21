---
title: "Building a Desktop LLM App with cpp-httplib"
order: 0

---

自分のC++ライブラリにWeb APIを追加したい、Electronライクなデスクトップアプリをサクッと作りたい―そう思ったことはありませんか？ Rustなら「Tauri + axum」という選択肢がありますが、C++では難しいと諦めていませんか？

[cpp-httplib](https://github.com/yhirose/cpp-httplib)と[webview/webview](https://github.com/webview/webview)、そして[cpp-embedlib](https://github.com/yhirose/cpp-embedlib)を組み合わせれば、C++だけで同じアプローチが取れます。しかも配布しやすい、小さなシングルバイナリーのアプリケーションを作れます。

今回は、[llama.cpp](https://github.com/ggml-org/llama.cpp)を組み込んだLLM翻訳アプリを題材に、「REST API → SSEストリーミング → Web UI→デスクトップアプリ」と段階的に構築しながら、そのやり方を学んでいきましょう。もちろん、翻訳はあくまで題材です。llama.cppを自分のライブラリに置き換えれば、同じ構成で自分だけのアプリが作れます。

![Desktop App](app.png#large-center)

C++17の基本文法とHTTP（REST API）の基本がわかれば、すぐに始められます。🚀

## 目次

1. **[プロジェクト環境を作る](ch01-setup)** — 依存ライブラリの取得、ビルド設定、雛形コード
2. **[llama.cppを組み込んでREST APIを作る](ch02-rest-api)** — JSONで翻訳結果を返すAPIの実装
3. **[SSEでトークンストリーミングを追加する](ch03-sse-streaming)** — トークン単位の逐次レスポンス
4. **[モデルの取得・管理機能を追加する](ch04-model-management)** — Hugging Faceからのダウンロードと切り替え
5. **[Web UIを追加する](ch05-web-ui)** — ブラウザから操作できる翻訳画面
6. **[WebViewでデスクトップアプリ化する](ch06-desktop-app)** — シングルバイナリのデスクトップアプリ
7. **[llama.cpp本家のサーバー実装をコードリーディング](ch07-code-reading)** — プロダクション品質のコードとの比較
8. **[自分だけのアプリにカスタマイズする](ch08-customization)** — 自分のライブラリへの差し替えと応用
