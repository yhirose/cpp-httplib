---
title: "S18. listen_after_bindで起動順序を制御する"
order: 37
status: "draft"
---

普通は`svr.listen("0.0.0.0", 8080)`でbindとlistenをまとめて行いますが、bindした直後に何か処理を差し挟みたいときは、2つを分けて呼べます。

## bindとlistenを分ける

```cpp
httplib::Server svr;

svr.Get("/", [](const auto &, auto &res) { res.set_content("ok", "text/plain"); });

if (!svr.bind_to_port("0.0.0.0", 8080)) {
  std::cerr << "bind failed" << std::endl;
  return 1;
}

// ここでbindは完了。まだacceptは始まっていない
drop_privileges();
signal_ready_to_parent_process();

svr.listen_after_bind(); // acceptループを開始
```

`bind_to_port()`でポートの確保までを行い、`listen_after_bind()`で実際の待ち受けを開始します。この2段階に分けることで、bindとacceptの間に処理を挟めます。

## よくある用途

**特権降格**: 1023以下のポートにbindするにはroot権限が必要です。bindだけroot権限で行って、その後に一般ユーザーに降格すれば、以降のリクエスト処理は権限が落ちた状態で走ります。

```cpp
svr.bind_to_port("0.0.0.0", 80);
drop_privileges();
svr.listen_after_bind();
```

**起動完了通知**: 親プロセスやsystemdに「準備完了」を通知してからacceptを開始できます。

**テストの同期**: テストコードで「サーバーがbindされた時点」を確実に捉えてからクライアントを動かせます。

## 戻り値のチェック

`bind_to_port()`は失敗すると`false`を返します。ポートが既に使われている場合などです。必ずチェックしてください。

```cpp
if (!svr.bind_to_port("0.0.0.0", 8080)) {
  std::cerr << "port already in use" << std::endl;
  return 1;
}
```

`listen_after_bind()`はサーバーが停止するまでブロックし、正常終了なら`true`を返します。

> **Note:** 空いているポートを自動で選びたいときはS17. ポートを動的に割り当てるを参照してください。こちらも内部では`bind_to_any_port()` + `listen_after_bind()`の組み合わせです。
