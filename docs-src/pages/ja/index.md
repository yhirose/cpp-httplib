---
title: "cpp-httplib"
order: 0
---

[cpp-httplib](https://github.com/yhirose/cpp-httplib)は、C++用のHTTP/HTTPSライブラリです。[`httplib.h`](https://github.com/yhirose/cpp-httplib/raw/refs/tags/latest/httplib.h) というヘッダーファイルを1枚コピーするだけで使えます。

C++でちょっとしたHTTPサーバーやクライアントが必要になったとき、すぐに動くものが欲しいですよね。cpp-httplibはまさにそのために作られました。サーバーもクライアントも、数行のコードで書き始められます。

APIはラムダ式をベースにした直感的な設計で、C++11以降のコンパイラーがあればどこでも動きます。Windows、macOS、Linux — お使いの環境をそのまま使えます。

HTTPSも使えます。OpenSSLやmbedTLSをリンクするだけで、サーバー・クライアントの両方がTLSに対応します。Content-Encoding（gzip, brotli等）、ファイルアップロードなど、実際の開発で必要になる機能もひと通り揃っています。WebSocketもサポートしています。

内部的にはブロッキングI/Oとスレッドプールを使っています。大量の同時接続を捌くような用途には向きませんが、APIサーバーやツールの組み込みHTTP、テスト用のモックサーバーなど、多くのユースケースで十分な性能を発揮します。

「今日の課題を、今日中に解決する」— cpp-httplibが目指しているのは、そういうシンプルさです。

## ドキュメント

- [A Tour of cpp-httplib](tour/index) — 基本を順を追って学べるチュートリアル。初めての方はここから
- [Cookbook](cookbook/index) — 目的別のレシピ集。必要なトピックから読めます
