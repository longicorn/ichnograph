# アーキテクチャ決定: CLI

[English](adr.md)

## サブコマンドベースのCLIディスパッチと標準 `flag` パッケージの利用

**ステータス:** Accepted

`cmd/ichnograph` はサードパーティのCLIフレームワークを導入せず、引き続きGo標準ライブラリの `flag.NewFlagSet` をサブコマンド単位で使用します。これにより、[ルートアーキテクチャ決定](../adr.md)および[traceアーキテクチャ決定](../trace/adr.md)で確立された軽量な依存関係とサブコマンド間の分離を維持します。

従来の実装では各サブコマンドの `FlagSet.Usage` 上書きが1行のusage出力のみを行っており、個々のオプション説明が表示されませんでした。今後は各サブコマンドがusage行に加えて登録済みフラグ一覧（`PrintDefaults` または同等の整形出力）を出力するようにし、`ichnograph help <subcommand>` と `<subcommand> -h` / `--help` で一貫した完全なオプション説明を提供します。

内部フラグ `--ichnograph-exec-helper` は引き続き `main()` の先頭でサブコマンドディスパッチ前にインターセプトし、公開の `help` 出力からは除外します。

## ヘルプ出力先と終了コードの規約

**ステータス:** Accepted

ヘルプ表示とエラー出力について、一般的なPOSIXおよびGo CLIの慣習に従います。

- **明示的なヘルプ要求**（`ichnograph help`、`ichnograph help <subcommand>`、`ichnograph -h` / `--help`、`ichnograph <subcommand> -h` / `--help`）は `stdout` に出力して終了コード `0` で終了し、`less` や `grep` などのページャやパイプと組み合わせて利用できるようにします。
- **使用法エラーおよび引数エラー**（引数なし、未知のサブコマンド、未知のフラグ、必須引数の不足）は `stderr` にエラー詳細とあわせて `help` コマンドと同等のヘルプ内容（トップレベルまたは対象サブコマンド）を出力し、終了コード `2` で終了します。

Go標準の `flag.FlagSet` はデフォルトの出力先が `os.Stderr` であるため、`-h` / `--help`（`flag.ErrHelp`）のハンドリングでは出力先を `os.Stdout` に向ける（または `flag.ErrHelp` 時に `os.Stdout` へ明示的に出力する）一方、通常のパースエラーは `os.Stderr` に維持します。

## CLIリファレンスの集約とサブコマンドPRDへの委譲

**ステータス:** Accepted

[CLIプロダクト要求](prd.md)をルートCLIディスパッチ、`help` の振る舞い、共通規約、および全サブコマンドのオプション一覧を集約する単一のエントリーポイントとします。各サブコマンド固有の実行時動作、フィルタリングルール、JSONスキーマの詳細は各サブコマンドのPRD（[trace](../trace/prd.md)、[clew](../clew/prd.md)）に委譲し、ドキュメント間の重複を防ぎます。
