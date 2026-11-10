# ichnograph

[English](README.md)

Ichnographは、プロダクトの機能が何に依存し、何から影響を受けるかを実行環境に即して調べるためのツールです。実行時の観測結果とコード、ライブラリ、パッケージ、サービスなどの情報を依存関係のグラフで結び付け、コンポーネントの更新時などの影響調査に役立てることを目指します。

名前は**ichno**と**graph**を組み合わせたものです。ichnoは、生痕化石を表すichnofossilやichnite、生痕化石学を表すichnologyに含まれる語源です。さまざまな情報とその関係をまとめるという目標を名前に込めています。

現在は開発の初期段階です。最初のマイルストーンでは、Linuxでコマンドを実行し、eBPFを使ってファイルアクセス情報を収集します。詳しくは[プロダクト要求](docs/prd.ja.md)と[アーキテクチャ決定記録](docs/adr.ja.md)を参照してください。

## 試験的なファイルオープン収集

Linux上で `go build -o ichnograph ./cmd/ichnograph` を実行してビルドし、BPFプログラムのロードとトレースポイントへの接続に必要な権限で実行します。

```sh
sudo ./ichnograph -o result.json /path/to/command arg
```

既定では、記録されたパスまたは解決後のパスが`/var/log`配下、または`.log`で終わる記録を出力から除外します。含める場合は、コマンドの前に`-include-logs`を指定します（例: `sudo ./ichnograph -include-logs -o result.json /path/to/command`）。パスを解決できない場合や推定が不正確な場合は、除外漏れや誤った除外が起こり得ます。除外は収集とハッシュ計算の後に行うため、イベント量や損失は減りません。`.log.1`のようなローテーション後の名前は拡張子の条件には一致しません。

結果を書き出した後、ichnographは実行したコマンドの終了コードを返します。シグナルで終了した場合は、128にシグナル番号を加えた値を返します。コマンドが見つからない場合は127、実行できない場合は126を返します。

通常ファイルを1バイト以上読み取り、そのパスを解決できた後は、同一プロセスによる同じデバイスとinodeの読み取りを省略します。inodeの世代番号も取得できる場合は識別に使います。プロセスの開始時刻で再利用されたプロセスIDを区別し、開始時刻を取得できない場合は省略しません。1バイト以上の読み取りに成功してもパスを取得できない場合は、プロセスとファイルごとに最大100ミリ秒に1回、後続の読み取りで取得を試みます。失敗した読み取りや0バイトの読み取りでは、この間隔は始まりません。その間に終了したアクセスを見落とす場合があります。procfsでパスを解決できない場合は、以前のopenのパスを後からデバイスとinodeで照合し、一致すれば推定値として使います。推定値を含め、解決したパスは後から変わっている場合があります。世代番号で区別できないファイルシステムでのinodeの再利用や、別スレッドによるfdの変更で、後のアクセスを見落とす可能性があります。容量に上限のある追跡マップに識別情報を記録できない場合は、後続の読み取りも通常どおり記録します。通常ファイル以外の重複は省略しません。

`fifo_use_attempt`と`pipe_use_attempt`は、プロセスが名前付きFIFOまたは匿名pipeの読み書きを試みたことを記録します。追跡できる場合、プロセス・種類・読み書きごとに最初の試行を記録し、標準入出力も含めます。個々のpipe、通信相手のプロセス、パス、内容、処理結果は記録しません。種類の判定と集約はカーネルの状態に依存し、識別情報を取得できない場合やマップが満杯の場合は繰り返し記録されることがあります。

IPv4へのconnect記録は、PID、TID、fd、通信先、ソケット種類、直後の結果が同じ場合、収集後にまとめます。複数の試行をまとめた場合、`occurrences`に試行数を記録します。省略されている場合は1回です。時刻は最初の記録のものです。PID、TID、fdの再利用によって別の試行がまとまる場合があります。IPv6、Unixソケット、TCP状態を追跡する接続は集約しません。この集約は出力を整理するもので、リングバッファへのイベント量や損失は減りません。

`connect_attempt`は、プロセス、fd、指定されたIPv4またはIPv6のアドレスとポートを記録します。システムコールの直後の結果と、取得できる場合はソケットの種類（stream、datagram、seqpacket）も記録します。TCPでは、SYN_SENTから接続確立または確立前の切断への状態変化を`tcp_connect_outcome`として記録し、`connection_id`、PID、TIDで接続試行に対応付けます。確立前の切断はキャンセルと失敗の両方を含みます。対応する状態変化がない場合、最終結果は不明です。状態変化はシステムコールの終了より先に記録されることもあります。ソケットの種類だけではTCP・UDPを確定できません。IPv6のスコープID、Unixソケットのアドレス、その他のネットワーク操作、通信内容、関連ライブラリも記録しません。

/dev/null、/dev/zero、/dev/full、/dev/random、/dev/urandomとLinuxの仮想端末、シリアル端末、制御端末、コンソール、PTYのreadとwriteは、fd番号にかかわらず省略します。標準入出力のfd 0、1、2がパイプの場合も詳細なread/write記録を省略します。通常ファイルや判別できない端末は引き続き記録します。別スレッドによるfdの変更と種類の判定が競合する場合があります。この判定にはカーネルのBTFが必要です。

`loss_breakdown`にはリングバッファの予約失敗と、tracked、retry paths、mmap pending、write pending、TCP追跡の各マップの更新失敗を分けて記録します。各カウンターは別々に読み取るため、追跡中のプロセスが残っている場合は合計が`lost`と一致しないことがあります。

JSONにはexecve、execveat、open、creat、openat、openat2、読み取りとファイルを用いたmmapの試行、書き込みの記録、検出したイベント損失や追跡失敗の件数、収集上の制限が入ります。読み取り、open、exec、mmapは取得できた場合に成否を記録し、読み取りの成功時はバイト数も記録します。読み取り対象にはファイル以外の記述子も含まれます。終了イベントを取得できない場合やイベント損失によって対応付けが不確かになった場合、成否はnullになります。read、pread64、readv、preadv、preadv2を記録します。write、pwrite64、writev、pwritev、pwritev2で1バイト以上書き込んだ場合はwrite_observedとして記録します。失敗や0バイトの書き込み、バイト数、システムコールの種類は記録しません。通常ファイルへの繰り返しの書き込みは、パスを解決した後、プロセスとファイルごとに省略します。解決するまでは、書き込み成功後の再記録を最大100ミリ秒に1回に制限します。パスを解決できない短時間の書き込みや、ファイル識別情報の再利用、別スレッドによるfdの変更により、書き込みの見落としや誤認が起こる可能性があります。通常ファイル以外の重複は省略しません。ファイル以外の記述子も含まれ、記録は永続化を意味しません。メモリマップによる書き込みなどは対象外です。ファイルを用いたmmapの試行も記録しますが、マッピングの作成だけではデータを読み取ったことは分かりません。execの成功はスケジューラのexecトレースポイントで記録します。スレッドグループのリーダー以外によるexecでTIDが変化した場合も、同じトレースポイントを使って追跡を引き継ぎます。空パスのexecveatでは、記述子のパスを後から推定します。フラグは記録しません。列挙した以外のファイル操作は対象外です。記述子から推定したパスは後から取得したプロセス状態に基づくため、取得できない場合や不正確な場合があります。システムコールの開始時にパスを読み取れない場合は終了時に再試行します。取得できたパスは後から読み取ったことを明記し、ハッシュは計算しません。それでも読み取れない場合は、記録にカーネルのエラーを含めます。相対パスはそのまま残し、可能な場合は後から取得したプロセスの状態を使って推定した絶対パスを追加します。推定は不正確な場合や取得できない場合があり、ハッシュは計算しません。実行またはオープンに成功した絶対パスが読み取れる通常ファイルを指す場合は、収集後にハッシュを計算します。procfs上のファイルはプロセスや実行時の状態に内容が依存するため、シンボリックリンクや別のマウント先を経由した場合もハッシュを計算しません。`/proc/self`と`/proc/thread-self`を明示したパスも、収集後にはichnograph自身を指すため開く前に除外します。絶対パスごとのハッシュ計算は1回の収集につき1度だけ行い、その結果を各記録に使います。ハッシュは計算時の内容を示し、各アクセス時の内容とは限りません。読み取り用に開く前にファイル種別を確認し、確認したファイルをprocfs経由で非ブロッキングモードで開き直します。通常ファイルや疑似ファイルの読み取り時間には上限を設けていません。起動したコマンドの終了後も、追跡中の子孫が終了するまで最大1秒間収集を続けます。時間切れの時点で子孫が残っていれば`descendants_remaining`をtrueにし、それ以降の動作は収集しません。組み込みのBPFオブジェクトは現在リトルエンディアンのLinux向けで、カーネルのBPFリングバッファと、`open`、`creat`、`openat2`を含む監視対象のシステムコールと`sock:inet_sock_set_state`のトレースポイントがすべて必要です。これらが存在しないアーキテクチャでは現在実行できません。ロードや接続の失敗はエラーとして報告します。

ソースを変更した後に組み込みオブジェクトを再ビルドするには、BPFターゲットを備えたClangとLinuxヘッダーをインストールし、リトルエンディアンのマシンで次を実行します。

```sh
clang-18 -O2 -g -target bpf -I/usr/include/$(gcc -dumpmachine) -c internal/ebpf/program.c -o internal/ebpf/program.o
```

親子プロセスの追跡を確認するには、BPFの権限を持つホストで次を実行します。

名前付きFIFOと匿名pipeの記録は、BPFにアクセスできるホストで `sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 go test ./internal/ebpf -run '^TestPipeKinds$' -count=1 -v` を実行して確認できます。

処理中のTCP接続のキャンセルと、継承ソケットを使う接続は、BPFにアクセスできるホストで `sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 go test ./internal/ebpf -run '^TestTCPConnectInheritedAndCancel$' -count=1 -v` を実行して確認できます。

複数スレッドからの同時TCP接続の状態対応付けは、BPFにアクセスできるホストで `sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 go test ./internal/ebpf -run '^TestTCPConnectConcurrent$' -count=1 -v` を実行して確認できます。

同じfdを20回のTCP接続に再利用した場合の状態対応付けは、BPFにアクセスできるホストで `sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 go test ./internal/ebpf -run '^TestTCPConnectFDReuse$' -count=1 -v` を実行して確認できます。

非同期TCP接続の直後の結果と、対象プログラムがpollとSO_ERRORで確認した最終結果を比較するには、`sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 go test ./internal/ebpf -run '^TestNonblockingConnectOutcome$' -count=1 -v` を実行します。対応するTCP状態の記録を確認します。接続確立前の切断だけでは原因を特定できません。

Unixのstreamソケット、datagramソケット、接続エラー、非同期接続の結果は、BPFにアクセスできるホストで `sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 go test ./internal/ebpf -run '^TestConnectKinds$' -count=1 -v` を実行して確認できます。

特殊デバイスのreadとループバックへのconnect記録は、BPFにアクセスできるホストで `sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 go test ./internal/ebpf -run '^(TestSpecialDeviceReadSuppression|TestConnectObservation)$' -count=1 -v` を実行して確認できます。

端末と対象の特殊デバイスへの入出力の省略、および通常ファイルの書き込みの記録は、BPFとPTYにアクセスできるホストで `sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 go test ./internal/ebpf -run '^TestTerminalIOSuppression$' -count=1 -v` を実行して確認できます。

通常ファイルへの書き込みの集約とfd番号の再利用は、BPFにアクセスできるホストで `sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 go test ./internal/ebpf -run '^(TestWriteEvents|TestWriteDedupAndFDReuse)$' -count=1 -v` を実行して確認できます。

fd番号の再利用、継承ファイルの読み取り、別スレッドによるfdの付け替え、失敗直後の読み取り、短時間のファイルアクセスを確認するには、BPFとトレースポイントにアクセスできるホストで次を実行します。`TestReadCoverage`は各ケースのopenとパスを解決できたreadを報告します。サブテストの失敗は、既知のタイミング上の制限を含む証拠の欠落を示します。

```sh
sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 go test ./internal/ebpf -run '^(TestReadCoverage|TestInheritedRead)$' -count=1 -v
```

```sh
sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 go test ./internal/ebpf -run '^(TestChildProcess|TestInvalidPath|TestDirectoryFDPath|TestInheritedRead|TestShortLivedChildren|TestThreads|TestDescendantsAfterExit|TestDescendantWaitTimeout|TestCommandExitStatus|TestLegacyOpen|TestExecutableEvents|TestExecveat|TestExecveatEmptyPath|TestNonLeaderExec|TestKernelRingBufferLoss|TestCollectorLoss|TestLongPath|TestMissingFile|TestOpenat2|TestWriteEvents|TestProcSelfHash)$' -count=1 -v
```

これらのテストは、シェルとその子プロセスが同じファイルを開いた記録と、不正なパスアドレスのエラー報告、ディレクトリ記述子からの相対パスの推定、引き継いだ標準入力へのread、pread64、readv、preadv、preadv2、ファイルを用いたmmapを確認します。あわせて、短命な子プロセス20個と、同じプロセス内の複数スレッドによるファイルのオープン、親終了後の子孫の収集、待機の時間切れ、execveatの成功と失敗、BPFリングバッファが満杯になったときの損失報告を確認します。通常の非特権テストではスキップします。

既存のichnoと比較するには、両方の収集に必要な権限を持つホストで、ichno実行ファイルの絶対パスを指定します。

```sh
sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 ICHNO_BIN=/absolute/path/to/ichno go test ./internal/ebpf -run '^TestCompareIchno$' -count=1 -v
```

このテストは各ツールでシェルと、ファイルを開いた後もしばらく存続する子プロセスを別々に実行し、既知のファイルについてパス、PID、TID、時刻、MD5の記録を比較します。実際のPIDと時刻は実行ごとに異なります。ichnoが出力しないイベント種別についても表示します。

リーダー以外のスレッドからのexecの追跡を確認するには、権限のあるホストで次を実行します。

```sh
sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 go test ./internal/ebpf -run '^TestNonLeaderExec$' -count=1 -v
```

このテストは、execの成功記録と、その後のファイルオープンを確認します。

`TestCollectorLoss`はリングバッファの読み取り開始を意図的に遅らせ、実際のイベント損失がJSONに報告され、対応付けた結果が無効化されることを確認します。

`TestLongPath`は、取得バッファより長いパスのオープンに成功した場合、切り詰めの可能性が表示され、ハッシュが付かないことを確認します。

`TestMissingFile`は、存在しないファイルのオープン失敗とコマンドの終了ステータスを確認します。

`TestOpenat2`は、openat2の直接呼び出しの成功と失敗、および収集結果を確認します。

同じスレッドの開始イベントが重なった場合や、終了イベントが対応する開始イベントと一致しない場合、対象の結果と以後の同じTIDの結果は収集終了まで不明になります。TIDが再利用された場合も同様です。この制限は結果に表示されます。

`TestWriteEvents`は書き込み操作の成功とwriteの失敗を確認します。

`TestProcSelfHash`は、`/proc/self/status`と、そのシンボリックリンクのオープンに成功した記録に、収集後の誤解を招くハッシュが付かないことを確認します。

## Dockerでの実行

コンテナ内で`ichnograph`を実行するには、`--pid=host`または`pid: "host"`によるホストのPID名前空間の共有、eBPFプログラムのロードとトレースポイントへの接続に必要な権限、十分なロック可能メモリ上限である`RLIMIT_MEMLOCK`、および`/sys/kernel/tracing`の`tracefs`または`/sys/kernel/debug`の`debugfs`へのアクセスが必要です。

- ホストのPID名前空間を共有せずに分離されたPID名前空間で実行すると、コンテナ内のPIDとeBPFが観測するホスト側のPIDが一致せず、`"records": []`かつ`"descendants_remaining": true`になります。
- コンテナの権限または`RLIMIT_MEMLOCK`が不足していると、起動時に`load eBPF programs (requires BPF privileges): map ...: map create: operation not permitted (MEMLOCK may be too low, consider rlimit.RemoveMemlock)`というエラーで失敗します。
- コンテナ内に`tracefs`も`debugfs`もマウントされていない場合は、`privileged`を有効にしていてもトレースポイントへの接続時に`attach sched_process_fork: neither debugfs nor tracefs are mounted`というエラーで失敗します。

`docker run`で`--privileged`を使う場合は、次のように実行します。

```sh
docker run --rm -it \
  --pid=host \
  --privileged \
  --ulimit memlock=-1:-1 \
  -v /sys/kernel/tracing:/sys/kernel/tracing:rw \
  -v /sys/kernel/debug:/sys/kernel/debug:rw \
  <image> ./ichnograph -o result.json /path/to/command arg
```

`--privileged`を使わずに必要なケーパビリティを個別に指定する場合は、次のように実行します。

```sh
docker run --rm -it \
  --pid=host \
  --cap-add=BPF \
  --cap-add=PERFMON \
  --cap-add=SYS_ADMIN \
  --cap-add=IPC_LOCK \
  --security-opt seccomp=unconfined \
  --ulimit memlock=-1:-1 \
  -v /sys/kernel/tracing:/sys/kernel/tracing:rw \
  -v /sys/kernel/debug:/sys/kernel/debug:rw \
  <image> ./ichnograph -o result.json /path/to/command arg
```

Docker Composeの`compose.yaml`で`privileged`を使う場合は、次のように設定します。

```yaml
services:
  app:
    pid: "host"
    privileged: true
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - /sys/kernel/tracing:/sys/kernel/tracing:rw
      - /sys/kernel/debug:/sys/kernel/debug:rw
```

`compose.yaml`でケーパビリティを個別に指定する場合は、次のように設定します。

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

仮想マシン上で動作するコンテナ環境などでホスト側に`/sys/kernel/tracing`がマウントされていない場合は、特権コンテナ内で`ichnograph`を実行する前に`tracefs`をマウントします。

```sh
mount -t tracefs nodev /sys/kernel/tracing
```
