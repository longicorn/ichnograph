# ichnograph

[English](README.md)

Ichnographは、プログラムを実行した際にどのような構成要素が使われ、何に依存しているかを実行環境に即して把握するためのツールです。ファイル、プロセス、通信などの実行時の観測結果と、パッケージ、ライブラリ、ビルド成果物、サービスなどの情報を依存関係のグラフで結び付け、テスト実行の最適化やコンポーネント更新時の影響調査に役立てます。

名前は、生痕化石（ichnofossil / ichnite）や生痕化石学（ichnology）の語源である**ichno**と**graph**を組み合わせたもので、実行時の痕跡から関係性のグラフを組み立てる目標を表しています。

## ドキュメント

- プロダクト全体: [プロダクト要求](docs/prd.ja.md) | [アーキテクチャ決定記録](docs/adr.ja.md)
- Linux eBPFコレクタ: [eBPFプロダクト要求](docs/ebpf/prd.ja.md) | [eBPFアーキテクチャ決定記録](docs/ebpf/adr.ja.md)

## ビルドと使い方

Linux上でCLIをビルドし、eBPFプログラムのロードとトレースポイントへのアタッチに必要な権限で実行します。

```sh
go build -o ichnograph ./cmd/ichnograph
sudo ./ichnograph trace -o result.json /path/to/command arg
```

- 既定では、収集後にパスまたは解決済みパスが`/var/log`配下にあるレコードや`.log`で終わるレコードを除外します。含める場合は`-include-logs`を指定します。
  ```sh
  sudo ./ichnograph trace -include-logs -o result.json /path/to/command arg
  ```
- 結果を書き出したあと、`ichnograph`は対象コマンドの終了コードを返します（シグナル終了時は`128 + シグナル番号`、コマンドが見つからない場合は`127`、実行できない場合は`126`）。

`clew`は特権なしでトレース結果を処理します。レコードをプロセスとスレッドごとにまとめ、フィルタやタグ付けを行えます。

```sh
./ichnograph clew -include 'success=true' -tag 'gem:path~=/gem/ruby/' -o grouped.json result.json
```

入力と出力の既定値はそれぞれ標準入力と標準出力なので、`clew`をパイプでつなげます。条件式には完全一致の`field=value`と部分文字列一致の`field~=value`を使います。詳しくは[clewのプロダクト要求](docs/clew/prd.ja.md)を参照してください。

`help`でサブコマンドやオプションを確認できます。

```sh
./ichnograph help
./ichnograph help trace
./ichnograph help clew
```

観測対象のイベント、重複排除、パス解決、ハッシュ計算、損失報告の詳細は[eBPFプロダクト要求](docs/ebpf/prd.ja.md)と[eBPFアーキテクチャ決定記録](docs/ebpf/adr.ja.md)を参照してください。

## 開発とテスト

`internal/ebpf/program.c`を変更したあとに組み込みのeBPFオブジェクト（`internal/ebpf/program.o`）を再ビルドするには、BPFターゲットに対応したClangとLinuxカーネルヘッダーをリトルエンディアンのLinuxホストに用意して次を実行します。

```sh
clang-18 -O2 -g -target bpf -I/usr/include/$(gcc -dumpmachine) -c internal/ebpf/program.c -o internal/ebpf/program.o
```

通常のユニットテストを実行します。

```sh
go test ./...
```

BPFとトレースポイントの権限を持つLinuxホストで、eBPF統合テスト一式を実行します。

```sh
sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 go test ./internal/ebpf -count=1 -v
```

## Dockerでの実行

コンテナ内で`ichnograph`を実行するには、ホストのPID名前空間の共有（`--pid=host`または`pid: "host"`）、BPFおよびトレースポイントの権限、ロック可能メモリ上限の解除（`RLIMIT_MEMLOCK`）、および`/sys/kernel/tracing`（`tracefs`）または`/sys/kernel/debug`（`debugfs`）へのアクセスが必要です。

`docker run`で`--privileged`を使う場合は、次のように実行します。

```sh
docker run --rm -it \
  --pid=host \
  --privileged \
  --ulimit memlock=-1:-1 \
  -v /sys/kernel/tracing:/sys/kernel/tracing:rw \
  -v /sys/kernel/debug:/sys/kernel/debug:rw \
  <image> ./ichnograph trace -o result.json /path/to/command arg
```

`compose.yaml`で必要なケーパビリティを個別に指定する場合は、次のように設定します。

```yaml
services:
  app:
    pid: "host"
    cap_add:
      - BPF
      - PERFMON
      - SYS_ADMIN
      - IPC_LOCK
    security_opt:
      - seccomp:unconfined
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - /sys/kernel/tracing:/sys/kernel/tracing:rw
      - /sys/kernel/debug:/sys/kernel/debug:rw
```

仮想マシン上のコンテナ環境などでホスト側に`/sys/kernel/tracing`がマウントされていない場合は、特権コンテナ内で実行前に`tracefs`をマウントします。

```sh
mount -t tracefs nodev /sys/kernel/tracing
```
