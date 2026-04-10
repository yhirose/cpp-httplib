---
title: "S16. クライアントが切断したか検出する"
order: 35
status: "draft"
---

長時間のレスポンスを返している最中に、クライアントが接続を切ってしまうことがあります。無駄に処理を続けても意味がないので、適宜チェックして中断できるようにしておきましょう。cpp-httplibでは`req.is_connection_closed()`で確認できます。

## 基本の使い方

```cpp
svr.Get("/long-task", [](const httplib::Request &req, httplib::Response &res) {
  for (int i = 0; i < 1000; ++i) {
    if (req.is_connection_closed()) {
      std::cout << "client disconnected" << std::endl;
      return;
    }

    do_heavy_work(i);
  }

  res.set_content("done", "text/plain");
});
```

`is_connection_closed()`は`std::function<bool()>`なので、`()`を付けて呼び出します。切断されていれば`true`を返します。

## ストリーミングレスポンスと組み合わせる

`set_chunked_content_provider()`でストリーミング配信しているときも、同じ方法で切断を検出できます。ラムダにキャプチャしておくと便利です。

```cpp
svr.Get("/events", [](const httplib::Request &req, httplib::Response &res) {
  res.set_chunked_content_provider(
    "text/event-stream",
    [&req](size_t offset, httplib::DataSink &sink) {
      if (req.is_connection_closed()) {
        sink.done();
        return true;
      }

      auto event = generate_next_event();
      sink.write(event.data(), event.size());
      return true;
    });
});
```

切断を検出したら`sink.done()`を呼んで、プロバイダの呼び出しを止めます。

## どのくらいの頻度でチェックすべきか

毎ループで呼んでも軽い処理ですが、あまりに細かい単位で呼ぶと意味が薄れます。「1チャンクを生成し終えたタイミング」や「データベースの1クエリが終わったタイミング」など、**中断しても安全な境目**で確認するのが現実的です。

> **Warning:** `is_connection_closed()`の確認は即座に正確な値を返すとは限りません。TCPの特性上、送信が止まって初めて切断に気付くことも多いです。完璧なリアルタイム検出を期待せず、「そのうち気付ければいい」くらいの気持ちで使いましょう。
