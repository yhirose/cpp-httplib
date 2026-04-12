---
title: "S04. 静的ファイルサーバーを設定する"
order: 23
status: "draft"
---

HTML、CSS、画像などの静的ファイルを配信したいときは、`set_mount_point()`を使います。URLパスとローカルディレクトリを結びつけるだけで、そのディレクトリの中身がまるごと配信されます。

## 基本の使い方

```cpp
httplib::Server svr;
svr.set_mount_point("/", "./public");
svr.listen("0.0.0.0", 8080);
```

`./public/index.html`が`http://localhost:8080/index.html`で、`./public/css/style.css`が`http://localhost:8080/css/style.css`でアクセスできます。ディレクトリ構造がそのままURLに反映されます。

## 複数のマウントポイント

マウントポイントは複数登録できます。

```cpp
svr.set_mount_point("/", "./public");
svr.set_mount_point("/assets", "./dist/assets");
svr.set_mount_point("/uploads", "./var/uploads");
```

同じパスに複数のマウントを登録することもできます。その場合は登録順に探されて、見つかった最初のものが返ります。

## APIハンドラと組み合わせる

静的ファイルとAPIハンドラは共存できます。`Get()`などで登録したハンドラが優先され、マッチしなかったときにマウントポイントが探されます。

```cpp
svr.Get("/api/users", [](const auto &req, auto &res) {
  res.set_content("[]", "application/json");
});

svr.set_mount_point("/", "./public");
```

これでSPAのように、`/api/*`はハンドラで、それ以外は`./public/`から配信、という構成が作れます。

## MIMEタイプを追加する

拡張子からContent-Typeを決めるマッピングは組み込みですが、カスタムの拡張子を追加できます。

```cpp
svr.set_file_extension_and_mimetype_mapping("wasm", "application/wasm");
```

> **Warning:** 静的ファイル配信系のメソッドは**スレッドセーフではありません**。起動後（`listen()`以降）には呼ばないでください。起動前にまとめて設定しましょう。

> ダウンロード用のレスポンスを返したい場合は[S06. ファイルダウンロードレスポンスを返す](s06-download-response)も参考になります。
