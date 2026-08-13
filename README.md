# Invisible Unicode Check

[![ci](https://github.com/tkm112345/invisible-unicode-check/actions/workflows/ci.yml/badge.svg)](https://github.com/tkm112345/invisible-unicode-check/actions/workflows/ci.yml)

不可視 Unicode を使ってソースコードに悪意あるコードを潜り込ませる攻撃（[GlassWorm](https://xtech.nikkei.com/atcl/nxt/column/18/00989/040100204/) 型のペイロード埋め込み、[Trojan Source](https://trojansource.codes/)）を検出し、プルリクエストのマージをブロックする GitHub Action。

**npm パッケージを一切使いません。** Node.js の標準ライブラリのみで動作し、リポジトリに `package.json` を置いていないので `npm install` そのものが成立しません。サプライチェーン攻撃を検出するツールが、自分自身のサプライチェーンを持たない構成です。

## 使い方

```yaml
name: invisible-unicode

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0        # ベースコミットとの diff に必要
      - uses: tkm112345/invisible-unicode-check@v1
```

### マージを実際に止める設定

Action は失敗するだけで、マージボタンを止めるのは GitHub 側の設定です。

**Settings → Rules → Rulesets → New branch ruleset** で対象ブランチを指定し、
**Require status checks to pass** に `scan`（= job 名）を追加します。

> `on.pull_request` に `paths:` フィルタを付けないでください。フィルタでジョブがスキップされると required status check が永久に pending になり、マージ不能になります。

## 入力

| 入力 | 既定値 | 説明 |
| --- | --- | --- |
| `base-sha` | イベントから自動判定 | diff の基準コミット。PR なら `pull_request.base.sha`、push なら `before` |
| `exclude` | なし | 除外する glob。改行かカンマ区切り。`**` `*` `?` に対応 |

```yaml
      - uses: tkm112345/invisible-unicode-check@v1
        with:
          exclude: |
            locales/**
            *.po
```

## 検出ルール

### critical（マージをブロック）

| ID | 名前 | 対象 |
| --- | --- | --- |
| IUC001 | bidi-control | U+202A–202E, U+2066–2069（表示順を書き換えられる制御文字） |
| IUC002 | tag-character | U+E0000–E007F（不可視のペイロード運搬に使われる） |
| IUC003 | variation-selector-run | 1行に異体字セレクタが3個以上（GlassWorm のデータ埋め込み） |
| IUC004 | private-use | U+E000–F8FF ほか私用領域 |

### warning（ブロックしない）

| ID | 名前 | 対象 |
| --- | --- | --- |
| IUC005 | invisible-format | ZWSP/ZWNJ/ZWJ/soft hyphen/LRM/RLM などの不可視文字 |
| IUC006 | misplaced-bom | ファイル先頭以外に現れた BOM |

## 走査範囲

**PR が触れたファイル**だけを対象とし、その中で:

- **critical ルールはファイル全行**に適用する
- warning ルールは **PR が追加・変更した行のみ**に適用する

既存コードに埋まっているペイロードを見逃さない一方で、既存の絵文字や i18n テキストで PR がノイズだらけになるのを防ぐための線引きです。

ベースコミットが特定できない場合や `git diff` が失敗した場合は、警告を出したうえで**追跡中の全ファイルを全行スキャン**にフォールバックします。検査を黙ってスキップすることはありません。

ファイルパス自体も検査対象です（ファイル名に bidi override を仕込む攻撃があるため）。

## 設計上の判断

**異体字セレクタは「1行に3個以上」で判定する。** 絵文字（`⚠️` = U+26A0 U+FE0F）は正当に1個使うので、1〜2個は無視します。GlassWorm 型のペイロードは1行に数十個を連結するため、この閾値で分離できます。裏を返せば **2個ずつ複数行に分散されると検出できません**。閾値方式の限界として認識してください。

**LRM/RLM (U+200E/200F) は critical にしていない。** これらは i18n テキストで正当に使われ、かつ単体でコードの見た目を書き換える力が弱いためです。ブロックするのは埋め込み・上書き・分離の制御文字のみ。

**warning はマージをブロックしない。** ZWSP や BOM は誤検知しやすく、これでブロックすると運用側がチェックごと無効化してしまうためです。

## 限界

このツールが守るのは **自分のリポジトリに入ってくる PR** だけです。GlassWorm の実際の被害は npm パッケージや VS Code 拡張機能（Open VSX）経由の汚染であり、PR ゲートでは防げません。依存パッケージの取得物を検査する仕組みは別途必要です。

## 開発

```sh
node --test test/scan.test.js
```

テストは `String.fromCodePoint()` でペイロードを組み立てるため、このリポジトリ自体には不可視文字が1つも含まれていません（自己スキャンが通ります）。

## ライセンス

MIT
