---
title: "S21. マルチスレッド数を設定する"
order: 40
status: "draft"
---

cpp-httplibは、リクエストをスレッドプールで並行処理します。デフォルトでは`std::thread::hardware_concurrency() - 1`と`8`のうち大きいほうがベーススレッド数で、負荷に応じてその4倍まで動的にスケールします。スレッド数を明示的に調整したいときは、`new_task_queue`に自分でファクトリを設定します。

## スレッド数を指定する

```cpp
httplib::Server svr;

svr.new_task_queue = [] {
  return new httplib::ThreadPool(/*base_threads=*/8, /*max_threads=*/64);
};

svr.listen("0.0.0.0", 8080);
```

ファクトリは`TaskQueue*`を返すラムダです。`ThreadPool`にベーススレッド数と最大スレッド数を渡すと、負荷に応じて間のスレッド数が自動で増減します。アイドルになったスレッドは一定時間（デフォルトは3秒）で終了します。

## キューの上限も指定する

キューが溜まりすぎるとメモリを食うので、キューの最大長も指定できます。

```cpp
svr.new_task_queue = [] {
  return new httplib::ThreadPool(
    /*base_threads=*/12,
    /*max_threads=*/0,   // 動的スケーリング無効
    /*max_queued_requests=*/18);
};
```

`max_threads=0`にすると動的スケーリングが無効になり、固定の`base_threads`だけで処理します。`max_queued_requests`を超えるとリクエストが拒否されます。

## 独自のスレッドプールを使う

自前のスレッドプール実装を差し込むこともできます。`TaskQueue`を継承したクラスを作り、ファクトリから返します。

```cpp
class MyTaskQueue : public httplib::TaskQueue {
public:
  MyTaskQueue(size_t n) { pool_.start_with_thread_count(n); }
  bool enqueue(std::function<void()> fn) override { return pool_.post(std::move(fn)); }
  void shutdown() override { pool_.shutdown(); }

private:
  MyThreadPool pool_;
};

svr.new_task_queue = [] { return new MyTaskQueue(12); };
```

既存のスレッドプールライブラリがあるなら、そちらに委譲できるので、プロジェクト内でスレッド管理を統一したいときに便利です。

## ビルド時の調整

コンパイル時に変更したい場合は、マクロで初期値を設定できます。

```cpp
#define CPPHTTPLIB_THREAD_POOL_COUNT 16       // ベーススレッド数
#define CPPHTTPLIB_THREAD_POOL_MAX_COUNT 128   // 最大スレッド数
#define CPPHTTPLIB_THREAD_POOL_IDLE_TIMEOUT 5  // アイドル終了までの秒数
#include <httplib.h>
```

> **Note:** WebSocket接続はその生存期間中ずっと1スレッドを占有します。大量の同時WebSocket接続を扱うなら、動的スケーリングを有効にしておきましょう（`ThreadPool(8, 64)`のように）。
