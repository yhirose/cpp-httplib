---
title: "S20. Keep-Aliveを調整する"
order: 39
status: "draft"
---

`httplib::Server`はHTTP/1.1のKeep-Aliveを自動で有効にしています。クライアントから見ると接続が再利用されるので、TCPハンドシェイクのコストを毎回払わずに済みます。挙動を細かく調整したいときは、2つのセッターを使います。

## 設定できる項目

| API | デフォルト | 意味 |
| --- | --- | --- |
| `set_keep_alive_max_count` | 100 | 1本の接続で受け付けるリクエストの最大数 |
| `set_keep_alive_timeout` | 5秒 | アイドル状態の接続を閉じるまでの秒数 |

## 基本の使い方

```cpp
httplib::Server svr;

svr.set_keep_alive_max_count(20);
svr.set_keep_alive_timeout(10); // 10秒

svr.listen("0.0.0.0", 8080);
```

`set_keep_alive_timeout()`は`std::chrono`の期間を取るオーバーロードもあります。

```cpp
using namespace std::chrono_literals;
svr.set_keep_alive_timeout(10s);
```

## チューニングの目安

**アイドル接続が多くてリソースを食う**  
タイムアウトを短めに設定すると、遊んでいる接続がすぐに切れてスレッドが解放されます。

```cpp
svr.set_keep_alive_timeout(2s);
```

**APIが集中的に呼ばれて接続再利用の効果を最大化したい**  
1接続あたりのリクエスト数を増やすと、ベンチマークの結果が良くなります。

```cpp
svr.set_keep_alive_max_count(1000);
```

**とにかく接続を使い回したくない**  
`set_keep_alive_max_count(1)`にすると、1リクエストごとに接続が閉じます。デバッグや互換性検証以外ではあまりおすすめしません。

## スレッドプールとの関係

Keep-Aliveでつながりっぱなしの接続は、その間ずっとワーカースレッドを1つ占有します。接続数 × 同時リクエスト数がスレッドプールのサイズを超えると、新しいリクエストが待たされます。スレッド数の調整はS21. マルチスレッド数を設定するを参照してください。

> **Note:** クライアント側の挙動はC14. 接続の再利用とKeep-Aliveの挙動を理解するを参照してください。サーバーがタイムアウトで接続を切っても、クライアントは自動で再接続します。
