---
title: "Cookbook"
order: 0
status: "draft"
---

「〇〇をするには？」という問いに答えるレシピ集です。各レシピは独立しているので、必要なページだけ読めます。基本的な使い方は[Tour](../tour/)で紹介しています。

## クライアント

### 基本
- [C01. レスポンスボディを取得する / ファイルに保存する](c01-get-response-body)
- [C02. JSONを送受信する](c02-json)
- [C03. デフォルトヘッダーを設定する](c03-default-headers)
- [C04. リダイレクトを追従する](c04-follow-location)

### 認証
- [C05. Basic認証を使う](c05-basic-auth)
- [C06. BearerトークンでAPIを呼ぶ](c06-bearer-token)

### ファイル送信
- [C07. ファイルをマルチパートフォームとしてアップロードする](c07-multipart-upload)
- [C08. ファイルを生バイナリとしてPOSTする](c08-post-file-body)
- [C09. チャンク転送でボディを送る](c09-chunked-upload)

### ストリーミング・進捗
- [C10. レスポンスをストリーミングで受信する](c10-stream-response)
- [C11. 進捗コールバックを使う](c11-progress-callback)

### 接続・パフォーマンス
- [C12. タイムアウトを設定する](c12-timeouts)
- [C13. 全体タイムアウトを設定する](c13-max-timeout)
- [C14. 接続の再利用とKeep-Aliveの挙動を理解する](c14-keep-alive)
- [C15. 圧縮を有効にする](c15-compression)
- [C16. プロキシを経由してリクエストを送る](c16-proxy)

### エラー処理・デバッグ
- [C17. エラーコードをハンドリングする](c17-error-codes)
- [C18. SSLエラーをハンドリングする](c18-ssl-errors)
- [C19. クライアントにログを設定する](c19-client-logger)

## サーバー

### 基本
- S01. GET / POST / PUT / DELETEハンドラを登録する
- S02. JSONリクエストを受け取りJSONレスポンスを返す
- S03. パスパラメーターを使う（`/users/:id`）
- S04. 静的ファイルサーバーを設定する（`set_mount_point`）

### ストリーミング・ファイル
- S05. 大きなファイルをストリーミングで返す（`ContentProvider`）
- S06. ファイルダウンロードレスポンスを返す（`Content-Disposition`）
- S07. マルチパートデータをストリーミングで受け取る（`ContentReader`）
- S08. レスポンスを圧縮して返す（gzip）

### ハンドラチェーン
- S09. 全ルートに共通の前処理をする（Pre-routing handler）
- S10. Post-routing handlerでレスポンスヘッダーを追加する（CORSなど）
- S11. Pre-request handlerでルート単位の認証を行う（`matched_route`）
- S12. `res.user_data`でハンドラ間データを渡す

### エラー処理・デバッグ
- S13. カスタムエラーページを返す（`set_error_handler`）
- S14. 例外をキャッチする（`set_exception_handler`）
- S15. リクエストをログに記録する（Logger）
- S16. クライアントが切断したか検出する（`req.is_connection_closed()`）

### 運用・チューニング
- S17. ポートを動的に割り当てる（`bind_to_any_port`）
- S18. `listen_after_bind`で起動順序を制御する
- S19. グレースフルシャットダウンする（`stop()`とシグナルハンドリング）
- S20. Keep-Aliveを調整する（`set_keep_alive_max_count` / `set_keep_alive_timeout`）
- S21. マルチスレッド数を設定する（`new_task_queue`）
- S22. Unix domain socketで通信する（`set_address_family(AF_UNIX)`）

## TLS / セキュリティ

- T01. OpenSSL・mbedTLS・wolfSSLの選択指針（ビルド時の`#define`の違い）
- T02. SSL証明書の検証を制御する（無効化・カスタムCA・カスタムコールバック）
- T03. SSL/TLSサーバーを立ち上げる（証明書・秘密鍵の設定）
- T04. mTLS（クライアント証明書による相互認証）を設定する
- T05. サーバー側でピア証明書を参照する（`req.peer_cert()` / SNI）

## SSE

- E01. SSEサーバーを実装する
- E02. SSEでイベント名を使い分ける
- E03. SSEの再接続を処理する（`Last-Event-ID`）
- E04. SSEをクライアントで受信する

## WebSocket

- W01. WebSocketエコーサーバー／クライアントを実装する
- W02. ハートビートを設定する（`set_websocket_ping_interval`）
- W03. 接続クローズをハンドリングする
- W04. バイナリフレームを送受信する
