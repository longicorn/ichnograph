# プロダクト要求: CLI

[English](prd.md)

## 目的

本書は、`ichnograph` コマンドラインインターフェース（CLI）全体の仕様として、サブコマンド構成、共通規約、全オプション一覧、および `help` サブコマンドとヘルプ出力の要件を定義します。各サブコマンドの詳細な実行時動作およびデータスキーマは、[traceプロダクト要求](../trace/prd.md)および[clewプロダクト要求](../clew/prd.md)で定義します。

## コマンド構成

```sh
ichnograph <subcommand> [options] [arguments]
```

利用可能な公開サブコマンド:

- **`trace`**: 特権付きで対象コマンドを実行し、eBPFにより実行時の観測情報を収集してJSON出力します（[trace PRD](../trace/prd.md)）。
- **`clew`**: 非特権で `trace` または `clew` のJSON出力を後処理・グループ化します（[clew PRD](../clew/prd.md)）。
- **`help`**: トップレベルまたは指定したサブコマンドのヘルプを表示します。

> **注記:** `--ichnograph-exec-helper` フラグは `trace` 実行時の起動ハンドシェイクに用いられる内部実装用機構であり、公開サブコマンドやユーザー向けオプションではありません。ユーザー向けの `help` 一覧には表示しません。

## `help` コマンドおよびヘルプ出力

### トップレベルヘルプ

- 呼び出し形式: `ichnograph help`、`ichnograph -h`、`ichnograph --help`。
- トップレベルの使い方（usage）、各公開サブコマンド（`trace`、`clew`、`help`）の簡潔な説明、およびサブコマンドヘルプの参照方法（`ichnograph help <subcommand>`）を **標準出力（`stdout`）** に出力し、終了コード `0` で終了します。

### サブコマンドヘルプ

- 呼び出し形式: `ichnograph help <subcommand>`、`ichnograph <subcommand> -h`、`ichnograph <subcommand> --help`（`<subcommand>` は `trace`、`clew`、または `help`）。
- 対象サブコマンドの usage 行、簡潔な説明、およびサポートされている全オプション（フラグ名、引数形式、デフォルト値、説明）を **標準出力（`stdout`）** に出力し、終了コード `0` で終了します。

### 不正な呼び出しとエラー出力

- CLIの使用法エラー（引数なしの `ichnograph`、未知のサブコマンド（`ichnograph help <unknown>` を含む）、余分な引数（例: `ichnograph help trace extra`）、未知のフラグ、必須引数の不足など）が発生した場合は、エラーメッセージに加えて `help` コマンドと同等のヘルプ内容（ルートレベルのエラー時はトップレベルヘルプ、サブコマンド内のエラー時は対象サブコマンドのヘルプ）を **標準エラー出力（`stderr`）** に出力し、終了コード `2` で終了します。

## サブコマンドおよびオプション一覧

### `ichnograph trace`

```sh
ichnograph trace [-include-logs] -o output.json command [args...]
```

- **`-o <path>`（必須）**: 出力先 JSON ファイルのパス。
- **`-include-logs`（任意、デフォルト: `false`）**: `path` または `resolved_path` が `/var/log` 配下にある、または `.log` で終わるレコードを出力に含める。
- **`command [args...]`（必須）**: トレース対象として実行するコマンドとその引数。
- **終了コード**: トレースと出力書き込みが成功した場合は対象コマンドの終了コード（`0`〜`255`、シグナル終了時は `128 + signal`、見つからない場合は `127`、実行不可の場合は `126`）。CLI引数エラー時は `2`。トレースまたは出力失敗時は `1`。

### `ichnograph clew`

```sh
ichnograph clew [-group-by pid,tid] [-o output.json] [input.json]
```

- **`-group-by <keys>`（任意、デフォルト: `pid,tid`）**: 入力レコードのグループ化キー（現状は `pid,tid` のみサポート）。
- **`-o <path>`（任意、デフォルト: `-`）**: 出力先 JSON ファイルのパス（`-` の場合は標準出力 `stdout`）。
- **`input.json`（任意、デフォルト: `-`）**: 入力 JSON ファイルのパス（省略時または `-` の場合は標準入力 `stdin`）。
- **終了コード**: 成功時は `0`、CLI引数・オプション値の不正時は `2`、入力読込・JSONパース・検証・出力書き込み失敗時は `1`。

### `ichnograph help`

```sh
ichnograph help [subcommand]
```

- **`subcommand`（任意）**: 詳細ヘルプを表示する公開サブコマンド名（`trace`、`clew`、`help`）。省略時はトップレベルヘルプを表示します。
- **終了コード**: 成功時は `0`、未知のサブコマンドや余分な引数が渡された場合は `2`。

## 共通規約

- **出力ストリーム**: 明示的なヘルプ要求（`help`、`-h`、`--help`）は `stdout` に出力します。CLIの使用法エラーおよび実行時エラーは `stderr` に出力します。
- **終了コード**:
  - `0`: 成功、または明示的なヘルプ表示。
  - `2`: CLI構文エラー、未知のサブコマンド／フラグ、必須引数の不足。
  - `1`: 実行時エラー、I/Oエラー、またはJSON処理エラー。
  - `trace` でトレースおよびJSON出力が成功した場合は、対象コマンドの終了コードを透過します。
