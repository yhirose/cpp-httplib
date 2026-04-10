---
title: "S06. ファイルダウンロードレスポンスを返す"
order: 25
status: "draft"
---

ブラウザで開いたときにインラインで表示するのではなく、**ダウンロードダイアログ**を出したいときは、`Content-Disposition`ヘッダーを付けます。cpp-httplib側の特別なAPIではなく、普通のヘッダー設定で実現します。

## 基本の使い方

```cpp
svr.Get("/download/report", [](const httplib::Request &req, httplib::Response &res) {
  res.set_header("Content-Disposition", "attachment; filename=\"report.pdf\"");
  res.set_file_content("reports/2026-04.pdf", "application/pdf");
});
```

`Content-Disposition: attachment`を付けると、ブラウザが「保存しますか？」のダイアログを出します。`filename=`で保存時のデフォルト名を指定できます。

## 日本語など非ASCIIのファイル名

ファイル名に日本語やスペースが含まれる場合は、RFC 5987形式の`filename*`を使います。

```cpp
svr.Get("/download/report", [](const httplib::Request &req, httplib::Response &res) {
  res.set_header(
    "Content-Disposition",
    "attachment; filename=\"report.pdf\"; "
    "filename*=UTF-8''%E3%83%AC%E3%83%9D%E3%83%BC%E3%83%88.pdf");
  res.set_file_content("reports/2026-04.pdf", "application/pdf");
});
```

`filename*=UTF-8''`の後ろはURLエンコード済みのUTF-8バイト列です。古いブラウザ向けにASCIIの`filename=`も併記しておくと安全です。

## 動的に生成したデータをダウンロードさせる

ファイルがなくても、生成した文字列をそのままダウンロードさせることもできます。

```cpp
svr.Get("/export.csv", [](const httplib::Request &req, httplib::Response &res) {
  std::string csv = build_csv();
  res.set_header("Content-Disposition", "attachment; filename=\"export.csv\"");
  res.set_content(csv, "text/csv");
});
```

CSVエクスポートなどでよく使うパターンです。

> **Note:** ブラウザによっては`Content-Disposition`がなくても、Content-Typeを見て自動でダウンロード扱いにすることがあります。逆に、`inline`を付けるとできるだけブラウザ内で表示しようとします。
