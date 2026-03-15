---
title: "Building a Desktop LLM App with cpp-httplib"
order: 0
status: "draft"
---

llama.cpp を組み込んだ LLM 翻訳デスクトップアプリを段階的に構築しながら、cpp-httplib のサーバー・クライアント両面の使い方を実践的に学びます。翻訳は一例であり、この部分を差し替えることで要約・コード生成・チャットボットなど自分のアプリに応用できます。

## 依存ライブラリ

- [llama.cpp](https://github.com/ggml-org/llama.cpp) — LLM 推論エンジン
- [nlohmann/json](https://github.com/nlohmann/json) — JSON パーサー（ヘッダーオンリー）
- [webview/webview](https://github.com/webview/webview) — WebView ラッパー（ヘッダーオンリー）
- [cpp-httplib](https://github.com/yhirose/cpp-httplib) — HTTP サーバー/クライアント（ヘッダーオンリー）

## 章立て

1. **llama.cpp を組み込んで REST API を作る** — テキストを POST すると翻訳結果を JSON で返すシンプルな API から始める
2. **SSE でトークンストリーミングを追加する** — 翻訳結果をトークン単位で逐次返す LLM API 標準の方式を実装する
3. **モデルの取得・管理機能を追加する** — Hugging Face から GGUF モデルを検索・ダウンロードするクライアント機能を実装する
4. **Web UI を追加する** — 静的ファイル配信で翻訳 UI をホストし、ブラウザから操作できるようにする
5. **WebView でデスクトップアプリ化する** — webview/webview で包み、Electron 的なデスクトップアプリとして動作させる
6. **llama.cpp 本家のサーバー実装をコードリーディング** — 自分で作ったものとプロダクション品質のコードを比較して学ぶ
