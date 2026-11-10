# プロダクト要求: eBPFコレクタ

[English](prd.md)

## 目的

`internal/ebpf`コレクタは、Linux上で対象コマンドを実行し、ファイルアクセス、プログラム実行、ディスクリプタの使用、パイプおよびFIFOの活動、ネットワーク接続の試行をeBPFで捕捉します。[ichnograph全体のプロダクト要求](../prd.ja.md)の一部として、後続の依存関係調査に用いる構造化レコードと完全性に関するメタデータを返します。

## プロセスのライフサイクルと追跡

- 動的リンカなど起動直後のアクセスを取りこぼさないよう、対象コマンドの実行開始前に追跡を開始します。
- `fork`、スレッドグループリーダーのPID変化を含む`exec`遷移、およびスレッドの終了にわたって子プロセスとスレッドを追跡します。
- 対象コマンドの終了コードを返します。シグナルにより終了した場合は`128 + シグナル番号`を返します。
- ルートコマンドの終了後、追跡中の子孫スレッドが終了するまで最大1秒間待機します。タイムアウト後も子孫スレッドが残っている場合は`descendants_remaining`を`true`にし、以降の活動が捕捉されない旨を制限事項に記録します。

## 観測対象の操作とイベント粒度

各観測結果には`pid`、`tid`、`timestamp`、`event`、取得可能な場合の成否（`success`と操作別のエラー項目）、およびパス、ディスクリプタ、ネットワークに関する項目を記録します。

- **ファイルオープン試行（`open_attempt`）:** `open`、`creat`、`openat`、`openat2`を監視し、指定された`path`、`dirfd`、`success`、失敗時の`open_error`を記録します。システムコール入口でユーザ空間のパス名読み取りに失敗した場合は出口で再試行し、システムコール後に読み取った旨を`note`に記録します。
- **プログラム実行試行（`exec_attempt`）:** `execve`と`execveat`を監視し、`path`、`dirfd`、`success`、失敗時の`exec_error`を記録します。`execveat`で空のパス名が指定された場合は`dirfd`から対象パスの解決を試み、フラグが記録されない旨を`note`に記録します。
- **ファイルを伴うメモリマッピング（`mmap_attempt`）:** `MAP_ANONYMOUS`を持たない`mmap`呼び出しを監視し、`fd`、解決可能な場合のディスクリプタパス、`success`、失敗時の`mmap_error`を記録します。
- **ディスクリプタ読み取り（`read_attempt`, `pread_attempt`, `readv_attempt`, `preadv_attempt`, `preadv2_attempt`）:** `read`、`pread64`、`readv`、`preadv`、`preadv2`を監視し、`fd`、成功時の`bytes_read`または失敗時の`read_error`、および解決済みパス情報を記録します。
- **ディスクリプタ書き込み（`write_observed`, `write_attempt`, `pwrite_attempt`, `writev_attempt`, `pwritev_attempt`, `pwritev2_attempt`）:** `write`、`pwrite64`、`writev`、`pwritev`、`pwritev2`を監視します。イベント量を抑えるため、1バイト以上書き込まれた呼び出しのみを`write_observed`として記録し、0バイトの書き込みと失敗した書き込みは除外します。
- **パイプおよびFIFOの使用（`pipe_use_attempt`, `fifo_use_attempt`）:** 監視対象の読み書きがパイプまたはFIFOのディスクリプタを対象とする場合、プロセス、種別（パイプまたはFIFO）、方向（`read`または`write`）の組み合わせごとに初回のみ記録し、個々のパイプ識別子や成否は記録しない旨を`note`に明記します。
- **ネットワーク接続（`connect_attempt`, `tcp_connect_outcome`）:** `connect`を監視し、`fd`、`network`（`ipv4`、`ipv6`、`unix`またはファミリー番号の`family`、IPv4/IPv6の`address`と`port`、取得可能な場合の`socket_type`）、`success`、`connect_error`を記録します。ストリーム型のIPv4/IPv6接続が`EINPROGRESS`または`EALREADY`を返した場合は`success`を未設定として`connection_id`を付与し、ソケットが`TCP_SYN_SENT`から`TCP_ESTABLISHED`または`TCP_CLOSE`へ遷移した際に、対応する`tcp_connect_outcome`レコード（`established`または`closed_before_established`）を記録します。

## ノイズ抑制、重複排除、集約

実際のワークロードでリングバッファの帯域消費を抑えるため、以下の制御を行います。

- `/dev/null`、`/dev/zero`、`/dev/full`、`/dev/random`、`/dev/urandom`、Linux仮想端末、シリアルTTY、制御端末、コンソール、PTYに対する読み書きイベント、およびパイプである標準ディスクリプタ`0`、`1`、`2`に対する読み書きイベントを除外します。
- 通常ファイルについては、あるプロセスで1バイト以上の読み取りまたは書き込みに対してユーザ空間でパス解決が成功したあと、同一ファイル識別子（`dev`、`ino`、`generation`、`pid`、`process_start`）に対する以降の読み取り（`read_seen`）または書き込み（`write_seen`）を抑制します。パス解決が成功する前の再試行は、同一ファイル識別子につき100ミリ秒あたり最大1回に制限します。
- 収集完了後、非同期のTCP状態追跡を持たない（`connection_id == 0`）IPv4の`connect_attempt`レコードについて、`pid`、`tid`、`fd`、`address`、`port`、`socket_type`、即時結果、`connect_error`、`note`が一致するものを集約し、最初のタイムスタンプを保持して件数を`occurrences`に記録します。

## パス解決とファイルハッシュ

- **相対パス:** `..`を含まない相対パスの`open`または`exec`では、`/proc/<pid>/task/<tid>/cwd`（`AT_FDCWD`の場合）または`/proc/<pid>/task/<tid>/fd/<dirfd>`を基準に`resolved_path`を解決し、事後のプロセス状態を用いた旨を`note`に記録します。シンボリックリンクを跨ぐ誤解決を防ぐため、`..`を含むパスは解決しません。
- **ディスクリプタパス:** ディスクリプタを対象とするイベント（`read`、`write`、`mmap`、空パスの`execveat`）では、`/proc/<pid>/task/<tid>/fd/<fd>`から削除済み（`(deleted)`）でない絶対パスを取得できる場合に`resolved_path`として記録します。`/proc`からの解決に失敗した場合は、同じ`(pid, fd)`で先行する成功した`open`のパスが存在し、かつ現在のファイルの`(dev, ino)`がイベント発生時の通常ファイル識別子と一致する場合に限り、そのパスを採用します。
- **MD5ハッシュ:** 収集完了後、`success == true`で既存の`note`がなく、絶対パスの`path`を持つレコードについて`md5`を計算します。`/proc/self`、`/proc/thread-self`、通常ファイル以外、および`procfs`上のファイルは対象外とし、ハッシュを計算できない理由を`note`に記録します。

## 完全性、損失報告、限界の明示

- 失われたイベントの総数を`lost`に記録し、発生箇所別の内訳を`loss_breakdown`（`ring_buffer`、`tracked_map`、`retry_paths_map`、`mmap_pending_map`、`write_pending_map`、`tcp_tracking_map`）に記録します。
- イベント損失が1件でも発生した場合（`lost > 0`）、入口と出口の取り違えによる誤った結果を防ぐため、全レコードの`success`、各種エラー項目、`bytes_read`、`bytes_written`、および`open`相関や出口での再試行に依存するパスを消去します。
- 同一スレッド（`tid`）で入口と出口のイベントの重なりや不一致が検出された場合は、そのスレッドにおける以降の入口・出口の対応付けを無効化し、制限事項に記録します。
- 収集対象の範囲、重複排除の規則、取得タイミングに起因する制約、および実行中に発生した損失や相関の制限を`limitations`と各レコードの`note`に明記します。
