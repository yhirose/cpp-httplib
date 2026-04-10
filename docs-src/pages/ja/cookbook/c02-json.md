---
title: "C02. JSONを送受信する"
order: 2
status: "draft"
---

cpp-httplibにはJSONパーサーが含まれていません。JSONの組み立てや解析には[nlohmann/json](https://github.com/nlohmann/json)などのライブラリを使ってください。ここでは`nlohmann/json`を例に説明します。

## JSONを送信する

```cpp
httplib::Client cli("http://localhost:8080");

nlohmann::json j = {{"name", "Alice"}, {"age", 30}};
auto res = cli.Post("/api/users", j.dump(), "application/json");
```

`Post()`の第2引数にJSON文字列、第3引数にContent-Typeを渡します。`Put()`や`Patch()`でも同じ形です。

> **Warning:** 第3引数のContent-Typeを省略すると、サーバー側でJSONとして認識されないことがあります。`"application/json"`を必ず指定しましょう。

## JSONレスポンスを受け取る

```cpp
auto res = cli.Get("/api/users/1");
if (res && res->status == 200) {
  auto j = nlohmann::json::parse(res->body);
  std::cout << j["name"] << std::endl;
}
```

`res->body`は`std::string`なので、そのままJSONライブラリに渡せます。

> **Note:** サーバーがエラー時にHTMLを返すことがあります。ステータスコードを確認してからパースすると安全です。また、APIによっては`Accept: application/json`ヘッダーが必要です。JSON APIを繰り返し呼ぶならC03. デフォルトヘッダーを設定するが便利です。

> サーバー側でJSONを受け取って返す方法はS02. JSONリクエストを受け取りJSONレスポンスを返すを参照してください。
