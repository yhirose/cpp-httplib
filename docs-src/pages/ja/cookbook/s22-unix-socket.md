---
title: "S22. Unix domain socketで通信する"
order: 41
status: "draft"
---

ネットワーク経由ではなく、同じホスト内のプロセスとだけ通信したいときは、Unix domain socketを使えます。TCPのオーバーヘッドがなく、ファイルシステムのパーミッションで簡単にアクセス制御できるので、ローカルのIPCや、リバースプロキシの背後に置くサービスでよく使われます。

## サーバー側

```cpp
httplib::Server svr;
svr.set_address_family(AF_UNIX);

svr.Get("/", [](const auto &, auto &res) {
  res.set_content("hello from unix socket", "text/plain");
});

svr.listen("/tmp/httplib.sock", 80);
```

`set_address_family(AF_UNIX)`を呼んでから、`listen()`の第1引数にソケットファイルのパスを渡します。第2引数のポート番号は使われませんが、シグネチャの都合で何か渡す必要があります。

## クライアント側

```cpp
httplib::Client cli("/tmp/httplib.sock");
cli.set_address_family(AF_UNIX);

auto res = cli.Get("/");
if (res) {
  std::cout << res->body << std::endl;
}
```

`Client`のコンストラクタにソケットファイルのパスを渡し、`set_address_family(AF_UNIX)`を呼ぶだけです。あとは通常のHTTPリクエストと同じように書けます。

## 使いどころ

- **リバースプロキシとの連携**: nginxがUnix socket経由でバックエンドを呼ぶ構成は、TCPより高速で、ポート管理も不要です
- **ローカル専用API**: 外部からアクセスしないツール間通信
- **コンテナ内IPC**: 同じPodやコンテナ内でのプロセス間通信
- **開発環境**: ポート競合を気にしなくていい

## ソケットファイルの後始末

Unix domain socketはファイルシステム上にファイルを作ります。サーバー終了時に自動では消えないので、必要なら起動前に削除しておきましょう。

```cpp
std::remove("/tmp/httplib.sock");
svr.listen("/tmp/httplib.sock", 80);
```

## パーミッション

ソケットファイルのパーミッションで、どのユーザーからアクセスできるかをコントロールできます。

```cpp
svr.listen("/tmp/httplib.sock", 80);
// 別プロセスや別スレッドで
chmod("/tmp/httplib.sock", 0660); // オーナーとグループのみ
```

> **Warning:** Windowsでも一部バージョンでAF_UNIXがサポートされていますが、実装や挙動がプラットフォームによって違います。クロスプラットフォームで動かす場合は、十分にテストしてから本番に投入してください。
