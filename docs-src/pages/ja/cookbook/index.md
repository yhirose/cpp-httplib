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
- [S01. GET / POST / PUT / DELETEハンドラを登録する](s01-handlers)
- [S02. JSONリクエストを受け取りJSONレスポンスを返す](s02-json-api)
- [S03. パスパラメーターを使う](s03-path-params)
- [S04. 静的ファイルサーバーを設定する](s04-static-files)

### ストリーミング・ファイル
- [S05. 大きなファイルをストリーミングで返す](s05-stream-response)
- [S06. ファイルダウンロードレスポンスを返す](s06-download-response)
- [S07. マルチパートデータをストリーミングで受け取る](s07-multipart-reader)
- [S08. レスポンスを圧縮して返す](s08-compress-response)

### ハンドラチェーン
- [S09. 全ルートに共通の前処理をする](s09-pre-routing)
- [S10. Post-routing handlerでレスポンスヘッダーを追加する](s10-post-routing)
- [S11. Pre-request handlerでルート単位の認証を行う](s11-pre-request)
- [S12. `res.user_data`でハンドラ間データを渡す](s12-user-data)

### エラー処理・デバッグ
- [S13. カスタムエラーページを返す](s13-error-handler)
- [S14. 例外をキャッチする](s14-exception-handler)
- [S15. リクエストをログに記録する](s15-server-logger)
- [S16. クライアントが切断したか検出する](s16-disconnect)

### 運用・チューニング
- [S17. ポートを動的に割り当てる](s17-bind-any-port)
- [S18. `listen_after_bind`で起動順序を制御する](s18-listen-after-bind)
- [S19. グレースフルシャットダウンする](s19-graceful-shutdown)
- [S20. Keep-Aliveを調整する](s20-keep-alive)
- [S21. マルチスレッド数を設定する](s21-thread-pool)
- [S22. Unix domain socketで通信する](s22-unix-socket)

## TLS / セキュリティ

- [T01. OpenSSL・mbedTLS・wolfSSLの選択指針](t01-tls-backends)
- [T02. SSL証明書の検証を制御する](t02-cert-verification)
- [T03. SSL/TLSサーバーを立ち上げる](t03-ssl-server)
- [T04. mTLSを設定する](t04-mtls)
- [T05. サーバー側でピア証明書を参照する](t05-peer-cert)

## SSE

- [E01. SSEサーバーを実装する](e01-sse-server)
- [E02. SSEでイベント名を使い分ける](e02-sse-event-names)
- [E03. SSEの再接続を処理する](e03-sse-reconnect)
- [E04. SSEをクライアントで受信する](e04-sse-client)

## WebSocket

- [W01. WebSocketエコーサーバー／クライアントを実装する](w01-websocket-echo)
- [W02. ハートビートを設定する](w02-websocket-ping)
- [W03. 接続クローズをハンドリングする](w03-websocket-close)
- [W04. バイナリフレームを送受信する](w04-websocket-binary)
