---
title: "W03. 接続クローズをハンドリングする"
order: 53
status: "draft"
---

WebSocket接続は、クライアントかサーバーのどちらかが明示的に閉じるか、ネットワーク障害で切れると終了します。クローズ処理をきちんと書いておくと、リソースの後始末や再接続ロジックがきれいに書けます。

## クローズ状態の検出

`ws.read()`が`ReadResult::Fail`を返したら、接続が切れたか何らかのエラーが起きたということです。ループを抜けてハンドラから戻れば、そのWebSocket接続の処理は終わります。

```cpp
svr.WebSocket("/chat", [](const httplib::Request &req, httplib::ws::WebSocket &ws) {
  std::string msg;
  while (ws.is_open()) {
    auto result = ws.read(msg);
    if (result == httplib::ws::ReadResult::Fail) {
      std::cout << "disconnected" << std::endl;
      break;
    }
    handle_message(ws, msg);
  }

  // ここに到達したら後始末
  cleanup_user_session(req);
});
```

`ws.is_open()`でも接続状態を確認できます。内部的には同じことを見ています。

## サーバー側から閉じる

サーバー側から明示的にクローズしたいときは、`close()`を呼びます。

```cpp
ws.close(httplib::ws::CloseStatus::Normal, "bye");
```

第1引数にクローズステータス、第2引数に理由（任意）を渡します。クローズステータスは`CloseStatus`列挙値で、代表的なものはこちらです。

| 値 | 意味 |
| --- | --- |
| `Normal` (1000) | 通常終了 |
| `GoingAway` (1001) | サーバーが終了するため |
| `ProtocolError` (1002) | プロトコル違反を検知 |
| `UnsupportedData` (1003) | 対応していないデータを受信 |
| `PolicyViolation` (1008) | ポリシー違反 |
| `MessageTooBig` (1009) | メッセージが大きすぎる |
| `InternalError` (1011) | サーバー内部エラー |

## クライアント側から閉じる

クライアント側でも同じAPIが使えます。

```cpp
cli.close(httplib::ws::CloseStatus::Normal);
```

`cli`を破棄したときにも自動的にクローズされますが、明示的に`close()`を呼んだほうが意図が伝わりやすいです。

## グレースフルシャットダウン

サーバーを停止するときに接続中のクライアントに「これから止まります」と伝えたい場合は、`GoingAway`を使います。

```cpp
ws.close(httplib::ws::CloseStatus::GoingAway, "server restarting");
```

クライアント側はこのステータスを見て、再接続を試みるかどうかを判断できます。

## サンプル: 簡単なチャット終了

```cpp
svr.WebSocket("/chat", [](const auto &req, auto &ws) {
  std::string msg;
  while (ws.is_open()) {
    if (ws.read(msg) == httplib::ws::ReadResult::Fail) break;

    if (msg == "/quit") {
      ws.send("goodbye");
      ws.close(httplib::ws::CloseStatus::Normal, "user quit");
      break;
    }

    ws.send("echo: " + msg);
  }
});
```

> **Note:** ネットワーク障害で突然切断された場合、`close()`を呼ぶ暇もなく`read()`が`Fail`を返します。後始末はハンドラ終了時にまとめて行うようにしておくと、どちらのパターンでも対応できます。
