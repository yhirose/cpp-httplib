---
title: "S19. グレースフルシャットダウンする"
order: 38
status: "draft"
---

サーバーを止めるには`Server::stop()`を呼びます。処理中のリクエストがある状態でも安全に呼べるので、SIGINTやSIGTERMを受け取ったときにこれを呼べば、グレースフルなシャットダウンが実現できます。

## 基本の使い方

```cpp
httplib::Server svr;

svr.Get("/", [](const auto &, auto &res) { res.set_content("ok", "text/plain"); });

std::thread t([&] { svr.listen("0.0.0.0", 8080); });

// メインスレッドで入力を待つなど
std::cin.get();

svr.stop();
t.join();
```

`listen()`はブロックするので、別スレッドで動かして、メインスレッドから`stop()`を呼ぶのが典型的なパターンです。`stop()`後は`listen()`が戻ってくるので、`join()`できます。

## シグナルでシャットダウンする

SIGINT（Ctrl+C）やSIGTERMを受け取ったときに停止させる例です。

```cpp
#include <csignal>

httplib::Server svr;

// グローバル領域に置いてシグナルハンドラからアクセス
httplib::Server *g_svr = nullptr;

int main() {
  svr.Get("/", [](const auto &, auto &res) { res.set_content("ok", "text/plain"); });

  g_svr = &svr;
  std::signal(SIGINT,  [](int) { if (g_svr) g_svr->stop(); });
  std::signal(SIGTERM, [](int) { if (g_svr) g_svr->stop(); });

  svr.listen("0.0.0.0", 8080);
  std::cout << "server stopped" << std::endl;
}
```

`stop()`はスレッドセーフで、シグナルハンドラの中から呼んでも安全です。`listen()`がメインスレッドで動いていても、シグナルを受けたら抜けてきます。

## 処理中のリクエストの扱い

`stop()`を呼ぶと、新しい接続は受け付けなくなりますが、すでに処理中のリクエストは**最後まで実行**されます。その後、スレッドプールのワーカーが順次終了し、`listen()`から戻ってきます。これがグレースフルシャットダウンと呼ばれる理由です。

> **Warning:** `stop()`を呼んでから`listen()`が戻るまでには、処理中のリクエストが終わるのを待つ時間がかかります。タイムアウトを強制したい場合は、シャットダウン用のタイマーを別途用意するなど、アプリケーション側の工夫が必要です。
