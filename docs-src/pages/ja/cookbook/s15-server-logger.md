---
title: "S15. リクエストをログに記録する"
order: 34
status: "draft"
---

サーバーが受け取ったリクエストと返したレスポンスをログに残したいときは、`Server::set_logger()`を使います。各リクエストの処理が完了するたびに呼ばれるので、アクセスログやメトリクス収集の土台になります。

## 基本の使い方

```cpp
svr.set_logger([](const httplib::Request &req, const httplib::Response &res) {
  std::cout << req.remote_addr << " "
            << req.method << " " << req.path
            << " -> " << res.status << std::endl;
});
```

ログコールバックには`Request`と`Response`が渡ります。メソッド、パス、ステータスコード、クライアントIP、ヘッダー、ボディなど、好きな情報を取り出せます。

## アクセスログ風のフォーマット

Apache / Nginxのアクセスログに似た形式で残す例です。

```cpp
svr.set_logger([](const auto &req, const auto &res) {
  auto now = std::time(nullptr);
  char timebuf[32];
  std::strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S",
                std::localtime(&now));

  std::cout << timebuf << " "
            << req.remote_addr << " "
            << "\"" << req.method << " " << req.path << "\" "
            << res.status << " "
            << res.body.size() << "B"
            << std::endl;
});
```

## 処理時間を測る

ログで処理時間を出したいときは、pre-routingハンドラで開始時刻を`res.user_data`に保存しておき、ロガーで差分を取ります。

```cpp
svr.set_pre_routing_handler([](const auto &req, auto &res) {
  res.user_data.set("start", std::chrono::steady_clock::now());
  return httplib::Server::HandlerResponse::Unhandled;
});

svr.set_logger([](const auto &req, const auto &res) {
  auto *start = res.user_data.get<std::chrono::steady_clock::time_point>("start");
  auto elapsed = start
    ? std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - *start).count()
    : 0;
  std::cout << req.method << " " << req.path
            << " " << res.status << " " << elapsed << "ms" << std::endl;
});
```

`user_data`の使い方は[S12. `res.user_data`でハンドラ間データを渡す](s12-user-data)も参照してください。

> **Note:** ロガーはリクエスト処理と同じスレッドで同期的に呼ばれます。重い処理を直接入れると全体のスループットが落ちるので、必要ならキューに流して非同期で処理しましょう。
