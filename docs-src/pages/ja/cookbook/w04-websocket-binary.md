---
title: "W04. バイナリフレームを送受信する"
order: 54
status: "draft"
---

WebSocketにはテキストフレームとバイナリフレームの2種類があります。JSONやプレーンテキストならテキスト、画像や独自プロトコルの生データならバイナリ、という使い分けです。cpp-httplibの`send()`は、オーバーロードで両者を自動的に切り替えます。

## 送り分けの仕組み

```cpp
ws.send(std::string("Hello"));           // テキスト
ws.send("Hello", 5);                      // バイナリ
ws.send(binary_data, binary_data_size);   // バイナリ
```

`std::string`を受け取るオーバーロードは**テキスト**、`const char*`とサイズを受け取るオーバーロードは**バイナリ**です。ちょっと紛らわしいですが、覚えてしまえば直感的です。

文字列をバイナリとして送りたい場合は、`.data()`と`.size()`を明示的に渡します。

```cpp
std::string raw = build_binary_payload();
ws.send(raw.data(), raw.size()); // バイナリフレーム
```

## 受信時の判別

`ws.read()`の返り値で、受信したフレームがテキストかバイナリかを判別できます。

```cpp
std::string msg;
auto result = ws.read(msg);

switch (result) {
  case httplib::ws::ReadResult::Text:
    std::cout << "text: " << msg << std::endl;
    break;
  case httplib::ws::ReadResult::Binary:
    std::cout << "binary: " << msg.size() << " bytes" << std::endl;
    handle_binary(msg.data(), msg.size());
    break;
  case httplib::ws::ReadResult::Fail:
    // エラーまたは切断
    break;
}
```

バイナリフレームも`std::string`に入って渡されますが、中身はバイト列なので注意してください。`msg.data()`と`msg.size()`で生のバイトとして扱えます。

## バイナリを使うべき場面

- **画像・動画・音声**: Base64でエンコードせずにそのまま送れるので、オーバーヘッドがない
- **独自プロトコル**: protobufやMessagePackなどの構造化バイナリフォーマット
- **ゲームのネットワーク通信**: 低レイテンシが求められる場合
- **センサーデータのストリーミング**: 数値列をそのまま送る

## Pingもバイナリフレームの一種

WebSocketのPing/PongフレームもOpcodeレベルではバイナリに近い扱いですが、cpp-httplibが自動で処理するので、アプリケーションコードで意識する必要はありません。W02. ハートビートを設定するを参照してください。

## サンプル: 画像を送る

```cpp
// サーバー側: 画像を送りつける
svr.WebSocket("/image", [](const auto &req, auto &ws) {
  auto img = read_image_file("logo.png");
  ws.send(img.data(), img.size());
});
```

```cpp
// クライアント側: 受け取ってファイルに保存
httplib::ws::WebSocketClient cli("ws://localhost:8080/image");
cli.connect();

std::string buf;
if (cli.read(buf) == httplib::ws::ReadResult::Binary) {
  std::ofstream ofs("received.png", std::ios::binary);
  ofs.write(buf.data(), buf.size());
}
```

テキストとバイナリを混ぜて送ることもできます。たとえば「制御メッセージはJSON、データ本体はバイナリ」といったプロトコルを組み立てると、メタデータと生データを効率よく扱えます。

> **Note:** WebSocketのフレームサイズには上限がないわけではありません。巨大なデータを送るときは、アプリケーション側で分割して送るのが安全です。cpp-httplibのデフォルトでは大きなフレームもそのまま処理されますが、メモリを一気に使う点は変わりません。
