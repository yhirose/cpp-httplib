---
title: "7. llama.cpp本家のサーバー実装をコードリーディング"
order: 7

---

6章かけてゼロから翻訳デスクトップアプリを作りました。動くものは完成しましたが、あくまで「学習用」の実装です。では「プロダクション品質」のコードはどう違うのか？ llama.cppに同梱されている公式サーバー`llama-server`のソースコードを読んで、比較してみましょう。

`llama-server`は`llama.cpp/tools/server/`にあります。同じcpp-httplibを使っているので、コードの読み方はこれまでの章と同じです。

## 7.1 ソースコードの場所

```ascii
llama.cpp/tools/server/
├── server.cpp           # メインのサーバー実装
├── httplib.h            # cpp-httplib（同梱版）
└── ...
```

ファイルは1つの`server.cpp`にまとまっています。数千行ありますが、構造を知っていれば読むべき箇所は絞れます。

## 7.2 OpenAI互換API

ここまで作ってきたサーバーと`llama-server`の最も大きな違いはAPIの設計です。

**私たちのAPI:**

```text
POST /translate          → {"translation": "..."}
POST /translate/stream   → SSE: data: "token"
```

**llama-serverのAPI:**

```text
POST /v1/chat/completions  → OpenAI互換のJSON
POST /v1/completions       → OpenAI互換のJSON
POST /v1/embeddings        → テキスト埋め込みベクトル
```

`llama-server`は[OpenAIのAPI仕様](https://platform.openai.com/docs/api-reference)に合わせています。つまり、OpenAIの公式クライアントライブラリ（Pythonの`openai`パッケージなど）がそのまま動きます。

```python
# OpenAIクライアントでllama-serverに接続する例
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8080/v1", api_key="dummy")

response = client.chat.completions.create(
    model="local-model",
    messages=[{"role": "user", "content": "Hello!"}]
)
```

既存のツールやライブラリとの互換性を持たせるかどうかは、大きな設計判断です。私たちは翻訳専用のAPIをシンプルに設計しましたが、汎用のサーバーを作るならOpenAI互換が事実上の標準になっています。

## 7.3 同時リクエスト処理

私たちのサーバーはリクエストを1つずつ処理します。翻訳中に別のリクエストが来ると、前の推論が終わるまで待ちます。1人で使うデスクトップアプリなら問題ありませんが、複数人で共有するサーバーでは困ります。

`llama-server`は**スロット**という仕組みで同時リクエストを処理します。

![llama-serverのスロット管理](../slots.svg#half)

ポイントは、各スロットのトークンを**1つずつ順番に**ではなく、**まとめて1回のバッチ**で推論することです。GPUは並列処理が得意なので、2人分を同時に処理しても1人分とほとんど変わらない時間で済みます。これを「連続バッチ処理（continuous batching）」と呼びます。

私たちのサーバーではcpp-httplibのスレッドプールが各リクエストに1スレッドを割り当てますが、推論自体は`llm.chat()`の中でシングルスレッドです。`llama-server`はこの推論部分を共有のバッチ処理ループに集約しています。

## 7.4 SSEフォーマットの違い

ストリーミングの仕組み自体は同じ（`set_chunked_content_provider` + SSE）ですが、送るデータのフォーマットが違います。

**私たちの形式:**

```text
data: "去年の"
data: "春に"
data: [DONE]
```

**llama-server（OpenAI互換）:**

```text
data: {"id":"chatcmpl-xxx","object":"chat.completion.chunk","choices":[{"delta":{"content":"去年の"}}]}
data: {"id":"chatcmpl-xxx","object":"chat.completion.chunk","choices":[{"delta":{"content":"春に"}}]}
data: [DONE]
```

私たちの形式はトークンだけを送るシンプルなものです。`llama-server`はOpenAI互換のため、1つのトークンにもJSONのラッパーが付きます。冗長に見えますが、`id`でリクエストを識別したり、`finish_reason`で停止理由を返せたりと、クライアントにとって便利な情報が含まれています。

## 7.5 KVキャッシュの再利用

私たちのサーバーでは、リクエストのたびにプロンプト全体をゼロから処理しています。翻訳アプリのプロンプトは短い（"Translate the following text to ja..." + 入力テキスト）ので、これで問題ありません。

`llama-server`は、前のリクエストと共通するプロンプトのprefixがある場合、その部分のKVキャッシュを再利用します。

![KVキャッシュの再利用](../kv-cache.svg#half)

長いシステムプロンプトやfew-shot例を毎回送るチャットボットでは、これだけで応答時間が大幅に短縮されます。数千トークンのシステムプロンプトを毎回処理するのと、キャッシュから一瞬で読むのとでは、体感が全く違います。

翻訳アプリではシステムプロンプトが1文だけなので効果は限定的ですが、自分のアプリに応用するときは意識したい最適化です。

## 7.6 構造化出力

翻訳APIはプレーンテキストを返すので、出力形式を制約する必要がありませんでした。でも、LLMにJSONで返させたい場合はどうでしょう？

```text
プロンプト: 以下の文の感情を分析してJSONで返してください。
LLMの出力（期待）: {"sentiment": "positive", "score": 0.8}
LLMの出力（現実）: 感情分析の結果は以下の通りです。{"sentiment": ...
```

LLMは指示を無視して余計なテキストを付けることがあります。`llama-server`はこの問題を**文法制約（grammar）**で解決しています。

```bash
curl http://localhost:8080/v1/chat/completions \
  -d '{
    "messages": [{"role": "user", "content": "Analyze sentiment..."}],
    "json_schema": {
      "type": "object",
      "properties": {
        "sentiment": {"type": "string", "enum": ["positive", "negative", "neutral"]},
        "score": {"type": "number"}
      },
      "required": ["sentiment", "score"]
    }
  }'
```

`json_schema`を指定すると、LLMのトークン生成時に文法に合わないトークンを除外します。出力が必ず有効なJSONになるので、`json::parse`が失敗する心配がありません。

LLMをアプリに組み込むとき、出力を確実にパースできるかどうかは信頼性に直結します。翻訳のようなフリーテキスト出力では不要ですが、APIのレスポンスとして構造化データを返す用途では必須の機能です。

## 7.7 まとめ

ここまでの違いを整理します。

| 観点 | 私たちのサーバー | llama-server |
|------|-------------|--------------|
| API設計 | 翻訳専用 | OpenAI互換 |
| 同時リクエスト | 1つずつ処理 | スロット+連続バッチ |
| SSEフォーマット | トークンのみ | OpenAI互換JSON |
| KVキャッシュ | 毎回クリア | prefixを再利用 |
| 構造化出力 | なし | JSON Schema/文法制約 |
| コード量 | 約200行 | 数千行 |

私たちのコードがシンプルなのは、「デスクトップアプリで1人が使う」という前提があるからです。複数人に提供するサーバーや、既存のエコシステムと連携するサーバーを作るなら、`llama-server`の設計が参考になります。

逆に言えば、200行のコードでも翻訳アプリとしては十分に動きます。「必要な分だけ作る」ことの価値も、このコードリーディングから感じてもらえたら嬉しいです。

## 次の章へ

次の章では、ここまで作ったアプリを自分のライブラリに差し替えてカスタマイズするためのポイントをまとめます。

**Next:** [自分だけのアプリにカスタマイズする](../ch08-customization)
