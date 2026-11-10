# アーキテクチャ決定記録: eBPFコレクタ

[English](adr.md)

## トレースポイントとBTF CO-REによる構成

**状態:** 採用

`internal/ebpf`のコレクタは、`sched`（`sched_process_fork`、`sched_process_exit`、`sched_process_exec`）、`syscalls`（`open`、`creat`、`openat`、`openat2`、`execve`、`execveat`、`read`、`pread64`、`readv`、`preadv`、`preadv2`、`write`、`pwrite64`、`writev`、`pwritev`、`pwritev2`、`connect`、`mmap`の`sys_enter_*`および`sys_exit_*`）、および`sock`（`inet_sock_set_state`）のLinuxカーネルトレースポイントにアタッチします。

カーネル内部のデータ構造（`task_struct`、`files_struct`、`fdtable`、`file`、`inode`、`super_block`、`socket`）は、BTF CO-RE（`__attribute__((preserve_access_index))`）を用いて読み取ります。コンパイル済みのBPFオブジェクト（`program.o`）を`//go:embed`でGoバイナリに埋め込み、`github.com/cilium/ebpf`でロードすることで、実行時に外部のCツールチェーンへ依存しない構成とします。収集の実行にはBPF権限が必要です。

## ヘルパー停止ハンドシェイクによる初期プロセスの追跡

**状態:** 採用

対象コマンドを直接起動してからユーザ空間で`tracked` BPFマップにPIDを登録すると、子プロセスの初期実行と競合し、起動直後のイベントを取りこぼします。これを防ぐため、`internal/ebpf.Run`は対象コマンドを実行する前に自身の実行ファイルを`--ichnograph-exec-helper`付きで起動します。

ヘルパープロセスは`execve`を呼ぶ前に自身へ`SIGSTOP`を送って停止します。コレクタはプローブをアタッチした状態でヘルパーの停止を`Wait4`（`WUNTRACED`）で待ち受け、ヘルパーのTIDを`tracked`マップに登録し、リングバッファの読み取りを開始したうえで`SIGCONT`を送って再開させます。

## 2サイズのリングバッファイベントと協調的な重複排除

**状態:** 採用

実際のワークロードでリングバッファの帯域消費を抑えるため、BPFプログラムは用途に応じて2種類の固定サイズイベントを出力します。

- **288バイトのイベント（`struct event`）:** パス名やソケットアドレスを伴う操作（`open`系、`exec`系、`connect`、`mmap`、`exec_transition`）で使用し、256バイトのバッファを保持します。
- **64バイトのイベント（`struct fd_event`）:** ディスクリプタのみを扱う操作（`read`系、`write`出口、パイプおよびFIFOの観測、`connect`出口、TCP状態遷移）で使用し、パスバッファを省いて32バイトの`read_identity`構造体（`ino`、`process_start`、`dev`、`pid`、`generation`）のみを保持します。

ノイズ抑制と重複排除は、カーネル側とユーザ空間側で役割を分担して行います。

- **カーネル側でのデバイスおよび標準入出力フィルタリング:** `ignored_io`がCO-REでディスクリプタのinodeモードとデバイス番号を調べ、`/dev/null`、`/dev/zero`、`/dev/full`、`/dev/random`、`/dev/urandom`、仮想端末、シリアルTTY、コンソール、PTY、およびパイプである標準ディスクリプタ`0`、`1`、`2`への読み書きをリングバッファ確保前に除外します。
- **書き込み出口でのフィルタリング:** `handle_write`はシステムコール入口で`write_pending`マップに情報を保持し、出口で`ret > 0`となった場合にのみ単一の`write_observed`イベントを出力します。これにより、失敗した書き込みや0バイトの書き込みによるリングバッファの消費を防ぎます。
- **通常ファイルの協調的な重複排除:** ユーザ空間でパス解決が成功する前にカーネル側で以降の読み書きを完全に抑制すると、初回の`/proc`参照が失敗した際にファイルパスを特定できなくなります。そのため、パス解決前の再試行はBPF側で`read_identity`ごとに100ミリ秒あたり1回へ制限し（`read_retry`および`write_retry`マップ）、1バイト以上の読み書きでパス解決が成功した時点（読み取りでは入口と出口の相関が曖昧でないことも条件）でユーザ空間から`read_seen`または`write_seen`マップへ登録して以降のイベントを抑制します。

## 不透明トークンによる非ブロッキングTCP接続の相関

**状態:** 採用

非ブロッキングのTCP `connect`はシステムコール出口で`-EINPROGRESS`や`-EALREADY`を返し、非同期に完了することが一般的です。IPv4およびIPv6のストリームソケットに対する`sys_enter_connect`では、BPFプログラムがCO-REで`struct socket -> sk`を読み取り、カーネルの`sk`ポインタから試行ごとのトークン（`ktime_get_ns()`）への対応を`tcp_connects`マップに保存します。別のエラーで即座に失敗した場合に解除できるよう、`tcp_entered`マップにも保持します。

`sock/inet_sock_set_state`が`TCP_SYN_SENT`から`TCP_ESTABLISHED`または`TCP_CLOSE`への遷移を観測した際、`tcp_connects`から`sk`を検索し、不透明なトークン（`connection_id`）のみを含む`tcp_connect_outcome`イベントを出力します。これにより、カーネルポインタをユーザ空間へ直接露出せずに非同期の接続結果を紐付けます。

## イベント後のパス解決と安全なファイルハッシュ計算

**状態:** 採用

eBPF内で完全なファイルシステムパスを解決したりファイル内容のハッシュを計算したりすることは、BPFベリファイアの制約上困難です。そのため、パス解決とハッシュ計算は安全上のガードを設けたうえでGoのユーザ空間で実行します。

- **相対パスとディスクリプタパスの解決:** ユーザ空間から`/proc/<pid>/task/<tid>/cwd`および`/proc/<pid>/task/<tid>/fd/<fd>`を参照します。`..`を含む相対パスは、事後にユーザ空間で結合するとシンボリックリンクを跨いで誤ったパスに解決されるおそれがあるため解決対象外とします。ディスクリプタが閉じられたあとなどで`/proc`からの解決に失敗した場合は、同じ`(pid, fd)`で先行する成功した`open`のパスに対し、`stat`で現在も通常ファイルであり`(dev, ino)`がイベント発生時と一致することが確認できた場合にのみ、そのパスを採用します。
- **安全なMD5計算:** 収集後に観測パスをそのまま`O_RDONLY`で開くと、FIFOでブロックしたりデバイスファイルで副作用を起こしたりするほか、`/proc/self`がコレクタ自身を指してしまう問題があります。`hashFile`はまず`O_PATH|O_CLOEXEC`で対象を開き、`fstat`と`fstatfs`によって対象が通常ファイルであり`procfs`（`PROC_SUPER_MAGIC`）上でないことを確認したうえで、検証済みinodeを`/proc/self/fd/<fd>`経由の`O_RDONLY|O_NONBLOCK|O_CLOEXEC`で開き直してMD5を計算します。

## イベント損失および相関曖昧時の保守的な無効化

**状態:** 採用

システムコール入口と出口のイベントはユーザ空間で`tid`ごとに対応付けられるため、リングバッファの損失や追跡・保留用マップの更新失敗が1件でも発生すると、TIDの再利用時を含め、別のシステムコールの入口と出口を誤って結び付けるおそれがあります。

- BPFプログラムは、`lost`配列マップに総損失数（インデックス`0`）と発生源別の損失数（`ring_buffer`、`tracked_map`、`retry_paths_map`、`mmap_pending_map`、`write_pending_map`、`tcp_tracking_map`）を記録します。
- `lost > 0`の場合、`invalidateOnLoss`は全レコードの`Success`、すべての`*Error`項目、`BytesRead`、`BytesWritten`、および出口での再試行や`open`相関から得たパスを一括で消去します。
- マップ上の損失カウンタとは独立に、同一`tid`で入口イベントの重複やイベント種別の不一致を検出した場合は、その`tid`を`uncertain`として記録し、当該スレッドにおける以降の入口・出口の相関を停止したうえで制限事項に追加します。
