---
title: "Cookbook"
order: 0
---

「〇〇をするには？」という問いに答えるレシピ集です。各レシピは独立しているので、必要なページだけ読めます。

## クライアント

### 基本
- レスポンスボディを文字列で取得する / ファイルに保存する
- JSON を送受信する
- デフォルトヘッダーを設定する（`set_default_headers`）
- リダイレクトを追従する（`set_follow_location`）

### 認証
- Basic 認証を使う（`set_basic_auth`）
- Bearer トークンで API を呼ぶ

### ファイル送信
- ファイルをマルチパートフォームとしてアップロードする（`make_file_provider`）
- ファイルを生バイナリとして POST する（`make_file_body`）
- チャンク転送でボディを送る（Content Provider）

### ストリーミング・進捗
- レスポンスをストリーミングで受信する
- 進捗コールバックを使う（`DownloadProgress` / `UploadProgress`）

### 接続・パフォーマンス
- タイムアウトを設定する（`set_connection_timeout` / `set_read_timeout`）
- 全体タイムアウトを設定する（`set_max_timeout`）
- 接続の再利用と Keep-Alive の挙動を理解する
- 圧縮を有効にする（`set_compress` / `set_decompress`）
- プロキシを経由してリクエストを送る（`set_proxy`）

### エラー処理・デバッグ
- エラーコードをハンドリングする（`Result::error()`）
- SSL エラーをハンドリングする（`ssl_error()` / `ssl_backend_error()`）
- クライアントにログを設定する（`set_logger` / `set_error_logger`）

## サーバー

### 基本
- GET / POST / PUT / DELETE ハンドラを登録する
- JSON リクエストを受け取り JSON レスポンスを返す
- パスパラメーターを使う（`/users/:id`）
- 静的ファイルサーバーを設定する（`set_mount_point`）

### ストリーミング・ファイル
- 大きなファイルをストリーミングで返す（`ContentProvider`）
- ファイルダウンロードレスポンスを返す（`Content-Disposition`）
- マルチパートデータをストリーミングで受け取る（`ContentReader`）
- レスポンスを圧縮して返す（gzip）

### ハンドラチェーン
- 全ルートに共通の前処理をする（Pre-routing handler）
- Post-routing handler でレスポンスヘッダーを追加する（CORS など）
- Pre-request handler でルート単位の認証を行う（`matched_route`）
- `res.user_data` でハンドラ間データを渡す

### エラー処理・デバッグ
- カスタムエラーページを返す（`set_error_handler`）
- 例外をキャッチする（`set_exception_handler`）
- リクエストをログに記録する（Logger）
- クライアントが切断したか検出する（`req.is_connection_closed()`）

### 運用・チューニング
- ポートを動的に割り当てる（`bind_to_any_port`）
- `listen_after_bind` で起動順序を制御する
- グレースフルシャットダウンする（`stop()` とシグナルハンドリング）
- Keep-Alive を調整する（`set_keep_alive_max_count` / `set_keep_alive_timeout`）
- マルチスレッド数を設定する（`new_task_queue`）

## TLS / セキュリティ

- OpenSSL・mbedTLS・wolfSSL の選択指針（ビルド時の `#define` の違い）
- SSL 証明書の検証を制御する（証明書の無効化・カスタム CA・カスタムコールバック）
- カスタム証明書検証コールバックを使う（`set_server_certificate_verifier`）
- SSL/TLS サーバーを立ち上げる（証明書・秘密鍵の設定）
- mTLS（クライアント証明書による相互認証）を設定する
- サーバー側でピア証明書を参照する（`req.peer_cert()` / SNI）

## SSE

- SSE サーバーを実装する
- SSE でイベント名を使い分ける
- SSE の再接続を処理する（`Last-Event-ID`）
- SSE をクライアントで受信する

## WebSocket

- WebSocket エコーサーバー／クライアントを実装する
- ハートビートを設定する（`set_websocket_ping_interval` / `CPPHTTPLIB_WEBSOCKET_PING_INTERVAL_SECOND`）
- 接続クローズをハンドリングする
- バイナリフレームを送受信する
