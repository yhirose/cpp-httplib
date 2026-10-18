---
title: "C17. エラーコードをハンドリングする"
order: 17
status: "draft"
---

`cli.Get()`や`cli.Post()`は`Result`型を返します。リクエストが失敗したとき（サーバーに到達できなかった、タイムアウトしたなど）、返り値は「falsy」になります（例外が1つあり、下の表で説明します）。詳しい原因を知りたい場合は`Result::error()`を使います。

## 基本の判定

```cpp
httplib::Client cli("http://localhost:8080");
auto res = cli.Get("/api/data");

if (res) {
  // リクエストが送れて、レスポンスも受け取れた
  std::cout << "status: " << res->status << std::endl;
} else {
  // ネットワーク層で失敗した
  std::cerr << "error: " << httplib::to_string(res.error()) << std::endl;
}
```

`if (res)`で成功・失敗を判定し、失敗時は`res.error()`で`httplib::Error`列挙値を取り出せます。`to_string()`に渡すと人間が読める文字列になります。

## 代表的なエラー

| 値 | 意味 |
| --- | --- |
| `Error::Connection` | サーバーに接続できなかった。または、使えないURL（authorityにuserinfoやバックスラッシュがある、ポートが不正など）から`Client`を作った。後者の場合は`cli.is_valid()`が`false`になる |
| `Error::ConnectionTimeout` | 接続タイムアウト（`set_connection_timeout`） |
| `Error::Read` / `Error::Write` | 送受信中のエラー。`set_read_timeout`や`set_max_timeout`によるタイムアウトも`Error::Read`になる |
| `Error::ExceedMaxPayloadSize` | レスポンスボディが`set_payload_max_length()`の上限を超えた（解凍後に超えた場合も含む） |
| `Error::Timeout` | `stream::Get()`や`SSEClient`で、ボディの読み取りがタイムアウトした |
| `Error::ExceedRedirectCount` | リダイレクト回数が上限を超えた |
| `Error::SSLConnection` | TLSハンドシェイクに失敗 |
| `Error::SSLServerVerification` | サーバー証明書の検証に失敗 |
| `Error::ProxyConnection` | プロキシがCONNECTのトンネルを拒否した。ただし407は例外で、`res`はtruthyかつ`res->status == 407`になり、`res.error()`は`Error::ProxyConnection`のまま |
| `Error::Canceled` | 進捗コールバック、`ContentReceiver`、`ResponseHandler`、アップロード用のコンテンツプロバイダのいずれかから`false`が返された |

## ステータスコードとの使い分け

`res`がtruthyでも、HTTPステータスコードが4xxや5xxのこともあります。この2つは別物です。

```cpp
auto res = cli.Get("/api/data");
if (!res) {
  // ネットワークエラー（そもそもレスポンスを受け取れていない）
  std::cerr << "network error: " << httplib::to_string(res.error()) << std::endl;
  return 1;
}

if (res->status >= 400) {
  // HTTPエラー（レスポンスは受け取った）
  std::cerr << "http error: " << res->status << std::endl;
  return 1;
}

// 正常系
std::cout << res->body << std::endl;
```

ネットワーク層のエラーは`res.error()`、HTTPのエラーは`res->status`、と頭の中で分けておきましょう。

> SSL関連のエラーをさらに詳しく調べたい場合は[C18. SSLエラーをハンドリングする](../c18-ssl-errors)を参照してください。
