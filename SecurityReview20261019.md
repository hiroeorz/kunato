# Kunato セキュリティレビュー

コードベース全体（`src/` 全モジュール、設定スキーマ、ルールエンジン、プロキシ経路、保護機構、ACME/更新系、`scripts/`、`packaging/`）を静的解析でレビューしました。

**環境上の制約**: 本セッションのワークスペースが UNC パス（`\\wsl.localhost\...`）にあるため、`pwsh` ツールがワークスペースの ACL 取得に失敗し、**コマンドを一切実行できませんでした**。したがって `cargo fmt` / `clippy` / `deny` / `test` は未実行で、以下の所見はすべてコード読解に基づきます（推測を含む箇所は明記します）。

---

## 1. 所見サマリ

| # | 重大度 | 概要 | 主な該当箇所 |
|---|---|---|---|
| **K-1** | **高** | 圧縮リクエストのデコード上限超過分が未検査のまま転送され、**小さなアップロードで body ルールを回避**できる | [src/proxy/server.rs:886](src/proxy/server.rs#L886), [src/decoding.rs:295](src/decoding.rs#L295) |
| **K-2** | **高** | リクエスト/レスポンス検査の**メモリ増幅**。1 本の HTTP/2 接続で約 1 GiB まで膨らみ、既定値のまま OOM 可能 | [src/decoding.rs:125](src/decoding.rs#L125), [src/proxy/server.rs:526](src/proxy/server.rs#L526), [src/proxy/response.rs:24](src/proxy/response.rs#L24) |
| **K-3** | **中** | **ALLOW の「完全アンカー必須」ガードレールのバイパス**（`^a\|b$`、`^a\$` が通過）。文書化された保証と実装が不一致 | [src/config/mod.rs:1866](src/config/mod.rs#L1866) |
| **K-4** | **中** | 検査コスト（本文サイズ×ルール数×デコード段数）がレート制限に反映されず、**CPU 増幅 DoS** | [src/rules/matcher.rs:176](src/rules/matcher.rs#L176), [src/protection/mod.rs:249](src/protection/mod.rs#L249) |
| **K-5** | **中** | HTTP/2 経路に header/idle タイムアウトがなく、**preface を送らない接続がスロットを永久占有**（Slowloris の h2 版） | [src/proxy/server.rs:526](src/proxy/server.rs#L526) |
| **K-6** | **中** | 追跡テーブル枯渇時に**新規クライアント全員が 503**。1 ホストの IPv6 /48 で持続可能 | [src/protection/mod.rs:156](src/protection/mod.rs#L156), [:189](src/protection/mod.rs#L189) |
| **K-7** | 低 | `ResponseView.body_truncated` が計算されるだけで未使用。応答ルールは完全性を要求できない | [src/request_view.rs:77](src/request_view.rs#L77), [src/proxy/response.rs:160](src/proxy/response.rs#L160) |
| **K-8** | 低 | 設定検証の穴（`shutdown_grace: 0` 許容、`limits.*` の上限なし、`is_fully_anchored` の偽陰性） | [src/config/mod.rs:1285](src/config/mod.rs#L1285), [:1268](src/config/mod.rs#L1268) |
| **K-9** | 低 | ACME 秘密鍵の一時ファイルが作成直後に既定権限、installer/upgrade のサプライチェーン留意点 | [src/acme.rs:244](src/acme.rs#L244), [scripts/install.sh:251](scripts/install.sh#L251) |

---

## 2. 詳細

### K-1【高】圧縮ボディのデコード打ち切りで body ルールを回避できる

**該当**: [src/proxy/server.rs:886-921](src/proxy/server.rs#L886)、[src/decoding.rs:25-68](src/decoding.rs#L25)、[src/decoding.rs:295-319](src/decoding.rs#L295)

`process()` は body ターゲットのルールがあるとき、生の prefix を `decode_content_encoding(body, headers, max_body_bytes)` で展開し、**展開結果を `inspected_body` として生バイトの代わりに**ルールへ渡します。

```rust
let decoded_body = if config.has_body_target_rules() {
    crate::decoding::decode_content_encoding(body, &parts.headers, config.limits.max_body_bytes)
} else { None };
...
let inspected_body = decoded_body.map(|decoded| decoded.body);
let inspected_body = inspected_body.as_deref().unwrap_or(body);   // ← 生バイトは見ない
```

`read_bounded()` は上限に達すると 1 バイトだけ probe して `truncated = true` にしますが、**その後の扱いはログとカウンタだけ**です（[:905-919](src/proxy/server.rs#L905)）。つまり:

- 攻撃者は `Content-Encoding: gzip` で「1 MiB の無害なパディング＋末尾に攻撃文字列」を gzip 圧縮して送る。
- 生 body は数 KB（`max_body_bytes` に収まる）なので `read_body` も通過。
- デコード出力は 1 MiB で打ち切られ、**それ以降の展開結果は一切検査されない**。
- Kunato は元の圧縮バイト（＝アプリが展開して攻撃として解釈するバイト列）をそのまま上流へ転送する。

結果、**1 KB 程度のリクエストで全 body ルール（SQLi/XSS/RCE/SSRF/deserialization 等）を回避**できます。非圧縮で同じことをするには 1 MiB 超のアップロードが必要なので、圧縮は約 1000 倍安価なバイパス手段です。

- `docs/attack-coverage.md:260` は「Content-Encoding Compression ✅」としていますが、**展開後サイズが上限を超えるケースでは未検査**であり、実態は Partial です。
- 同様の欠落は `deflate`/`br`/`zstd`、および「途中で展開エラーになった場合」にも起きます（`read_bounded` はエラー時も部分出力を返し `truncated=false` にしないため、**部分展開結果だけが検査対象**になる）。

**修正案**
1. `decoded.truncated == true` を**ポリシー化**する（既定で 413/400 拒否、または `on_truncated: block|inspect_raw|allow` を設定可能に）。少なくとも既定は「拒否」にしない限り WAF の検査保証が崩れます。
2. 展開が打ち切られた場合（または展開エラー時）は**生バイトも併せて検査**する（`body_forms` に raw prefix を残す）。
3. 圧縮入力の上限と展開出力の上限を分離し、`decoded_len > limit` を検知した時点で fail-closed にする。

---

### K-2【高】検査バッファのメモリ増幅（1 接続で約 1 GiB）

**該当**: [src/decoding.rs:125-146](src/decoding.rs#L125)、[src/request_view.rs:47](src/request_view.rs#L47)、[src/proxy/server.rs:526-533](src/proxy/server.rs#L526)、[src/proxy/response.rs:24-76](src/proxy/response.rs#L24)

既定ルールセットには body 条件のルールが 160 件以上あり（`rules.example.yaml` の `in: [body]` 166 箇所）、`has_body_target_rules()` が常に true になります。このとき 1 リクエストあたり同時に保持されるメモリは:

| バッファ | サイズ |
|---|---|
| `payload.prefix` | 最大 `max_body_bytes`（既定 1 MiB、Vec の伸長で最大 ~2 MiB） |
| 展開済み body（`Content-Encoding` 時） | 最大 1 MiB |
| `decode_body_formats` の出力（form/json/multipart） | 最大 ~1 MiB |
| `String::from_utf8_lossy(...).into_owned()` のコピー | ~1 MiB |
| `body_forms`（form 形＋percent pass 2 回の各コピー） | ~3 MiB |
| 応答側 `buffer_prefix` ＋ `decoded_prefix` | ~2 MiB |

→ **1 リクエストあたり約 4〜8 MiB**。HTTP/2 は `max_concurrent_streams`（既定 100）まで**同時に**処理されるため、**1 本の TCP 接続で 400〜800 MiB**、さらに接続上限 1024 まで考えると理論値は数 GiB です。`max_connections` は接続数しか数えないため、帯域 1 GiB 程度の送信で 8 GiB 級の RSS を作れます。

`docs/development.md:527-529` は「`max_concurrent_streams` は 1 接続が保持できる body バッファ量も制限する」としていますが、その「制限」は約 800 MiB であり安全な上限ではありません。

**修正案**
- `max_body_bytes` の既定値を下げる（例 64–256 KiB）、または
- 検査用バッファを「接続あたり／プロセス全体」で**合計上限**にする（セマフォで検査同時実行数を制限）、
- `body_forms` を `Vec<Vec<u8>>` で全コピーせず、パスごとにストリーミング/逐次評価する、
- 展開・整形の各段で `max_body_bytes` ではなく `min(max_body_bytes, remaining_budget)` を渡す。

なお **レート制限は body 読み込み後**（[src/proxy/server.rs:850](src/proxy/server.rs#L850)）に行われるため、バンスト状態でも 1 MiB の読み込みは発生します。`check_request` を `read_body` の前に移すことも有効です。

---

### K-3【中】ALLOW パターンの「完全アンカー」検証に穴がある

**該当**: [src/config/mod.rs:1866-1886](src/config/mod.rs#L1866)、呼び出し [:1834](src/config/mod.rs#L1834) / [:2070](src/config/mod.rs#L2070) / [:2106](src/config/mod.rs#L2106)

```rust
(rest.starts_with('^') || rest.starts_with(r"\A"))
    && (pattern.ends_with('$') || pattern.ends_with(r"\z"))
```

この判定は「先頭が `^`／末尾が `$`」という**バイト列の見た目**しか見ていません。以下はすべて「完全アンカー」と誤認されます。

1. **トップレベルの選択（alternation）**
   `^q=tokenfree|q=abc$` → 受理されるが、実際の正規表現は `^q=tokenfree` **または** `q=abc$`。
   ALLOW ルールが `^q=tokenfree|q=abc$` と書かれていると、`?q=tokenfree&<攻撃>` が `^q=tokenfree` に前方一致して **ALLOW が発火し WAF が無効化**されます。これはまさに `docs/attack-coverage.md:267` / `docs/development.md:452-458` が「拒否される」と保証している shadowing 攻撃です。
2. **エスケープされた `$`**
   `^cost=\$` は末尾バイトが `$` なので受理されるが、`\$` はリテラルのドル記号で**終端アンカーではない**。`cost=$<任意>` にマッチします。
3. （逆方向の軽微な不具合）`(?:^a$)` のような**非捕捉グループで包んだ正しい**パターンは受理されません（偽陰性）。前者を直すなら AST ベースの判定に置き換えるのが確実です。

**再現（検証用 YAML）**
```yaml
categories:
  - name: trusted-marker
    action: ALLOW
    rules:
      - name: marker
        match: { regex: '^q=tokenfree|q=abc$', in: [query] }
```
`GET /secret?q=tokenfree&q='%20OR%201=1` が ALLOW で素通りします（本来の意図は `^(q=tokenfree|q=abc)$`）。

**修正案**: 正規表現を AST にパースして「先頭が `\A`/`^` かつ末尾が `\z`/`$` で、トップレベルに `|` が無い」ことを検証する。あるいは `regex-syntax` で `Hir` を取り、`Concat` の最初/最後が `Look(Start)`/`Look(End)` であることを確認する（`regex-syntax` は `regex` の依存として既にツリー内にあります）。

---

### K-4【中】検査コストがレート制限に反映されない（CPU 増幅 DoS）

**該当**: [src/rules/matcher.rs:176-276](src/rules/matcher.rs#L176)、[src/protection/mod.rs:249-266](src/protection/mod.rs#L249)

1 リクエストの評価コストは `本文サイズ × body ルール数 × 本文フォーム数` に比例します。既定構成では:

- 非パス条件付きの汎用ルール（sql-injection / command-injection / xss / path-traversal / ssrf / ssti / ldap / xpath / nosql など）が約 50 件、`body` をスキャン
- 本文フォームは raw ＋ form デコード ＋ percent 2 パス ≒ 4 種類
- 各 1 MiB → 1 リクエストあたり **200 MiB 前後**の正規表現スキャン（数十 ms〜数百 ms の CPU）

一方、保護機構は**リクエスト数**しか数えません（`requests_per_second` / `global_requests_per_second`）。したがって「1 MiB の POST を 20 rps」で、既定のバンスト（＝レート制限に達していないので**バンも発動しない**）のまま数コアを消費させられます。IPv6 は `/64` 単位で別バケットなので、/48 を持つホストは 65k バケット × 20 rps まで拡張でき、グローバル上限（2000 rps）まで使い切れます。

**修正案**
- 検査バイト数に予算を設ける（例 `limits.max_inspection_bytes_per_request`、超過時は打ち切り＋警告＋fail-closed ポリシー）。
- 1 リクエストあたりスキャンするパターン総数を制限する、またはファストパス（リテラル・複数リテラル）を優先する順序にコンパイルする。
- レート制限の消費量をボディサイズで重み付けする（`cost = 1 + body_len/max_body_bytes`）。

---

### K-5【中】HTTP/2 経路に header/idle タイムアウトがない

**該当**: [src/proxy/server.rs:526-533](src/proxy/server.rs#L526)（h2 ビルダーのみ `header_read_timeout` を渡していない）、[src/proxy/server.rs:44-45](src/proxy/server.rs#L44)

```rust
Protocol::Http2 => {
    builder
        .timer(TokioTimer::new())
        .max_header_list_size(max_header_list_size)
        .max_concurrent_streams(max_concurrent_streams)
        .keep_alive_interval(Some(H2_KEEP_ALIVE_INTERVAL))
        .keep_alive_timeout(H2_KEEP_ALIVE_TIMEOUT);
```

`header_read_timeout` は **HTTP/1.1 ビルダーにしか設定されていません**（[:509](src/proxy/server.rs#L509)）。`keep_alive` の PING は「無応答の peer」を切るだけで、**応答を返し続ける攻撃者**は切れません。TLS + ALPN `h2` を受け入れ、preface（または途中のフレーム）を送らずに放置するだけで、接続スロット（既定 1024、per-IP 32）を無期限に占有できます。32 個の送信元 IP で全スロットを埋めると、新規クライアントは全て 503 になります。

> 注: hyper の h2 `handshake` が preface 待ちに独自のタイムアウトを持つかは未確認です（ソースを参照できないため）。少なくとも **このコードから h2 にタイムアウトを渡していない**ことは確実で、hyper 1.x の h2 Builder に header 読み取りタイムアウト相当の API はありません。

**修正案**: IO を `tokio::time::Timeout` でラップした `IdleTimeoutIo`（最後の読み取りから N 秒で `TimedOut`）を h2/h1 共通で適用する。または「最初のリクエストが N 秒以内に完了しなければ閉じる」監視を設ける。

---

### K-6【中】追跡テーブル枯渇による新規クライアントの全拒否

**該当**: [src/protection/mod.rs:156-193](src/protection/mod.rs#L156)、[:189-192](src/protection/mod.rs#L189)

`max_tracked_ips`（既定 100,000）を使い切ると、`client_shard` は `None` を返し、`check_request` は **`Overloaded`（503）** を返します。これは「未追跡ソースを黙って免除しない」という意図的な設計（`docs/DESIGN.md:384-388`）ですが、攻撃者視点では:

- IPv6 の `/48` を持つ 1 ホストで 65,536 個の `/64` キーを作成可能（`aggregate_ipv6_prefix: 64` のため `/64` ごとに別バケット）。
- 各キーは 600 秒以内に 1 回アクセスすれば `evict_stale` で消えない → 合計 ~167 rps で 100,000 エントリを維持。
- その間、**未知の送信元（＝新規の正規利用者）は全員 503**。

帯域・接続コストが小さく、WAF 自身が可用性攻撃の増幅器になります。

**修正案**: 満杯時は **LRU で最も古いエントリを追い出す**（fail-closed ではなく fail-open 的だが保護は継続）、または新規ソース用にテーブルの一定割合（例 5%）を予約する。併せて `Overloaded` を「新規ソースのみ」に限定し、既存ソースは通す。

---

### K-7【低】`ResponseView.body_truncated` が未使用

**該当**: [src/request_view.rs:73-94](src/request_view.rs#L73)、[src/proxy/response.rs:160-165](src/proxy/response.rs#L160)

`body_truncated` は構築されるだけで、`Matcher::matches_response` / `PayloadMatcher` のどこからも読まれません（grep で確認済み）。そのため:

- 応答ルールは「本文が途中までしか見えていない」ことを条件にできず、`max_response_body_bytes` を超えるパディングの後ろに機密文字列を置くことで `response-leaks` を回避できます。
- デッドフィールドであり、意図した安全機構が未配線である可能性が高いです。

**修正案**: 応答フェーズのマッチに `body_truncated` を渡し、`response_body` を対象とするルールは既定で「完全に読めた場合のみ」評価する（または `require_complete_body: true` を追加）。

---

### K-8【低】設定検証の細かな穴

**該当**: [src/config/mod.rs:1285-1297](src/config/mod.rs#L1285)、[:1268-1283](src/config/mod.rs#L1268)

- `validate_timeouts` は `header_read` / `body_read` / `upstream_connect` / `upstream_response` / `websocket_idle` を検査しますが、**`shutdown_grace` の 0 を許容**します（0 だと `drain_connections` が即 abort）。
- `limits.*` は「> 0」だけを検査し、**上限がありません**。`max_body_bytes: 1099511627776` のような設定は「Bounded resources」不変条件を事実上無効化します（`max_header_bytes` は h2 の `max_header_list_size` にそのまま渡るため、巨大値でヘッダバッファを膨張させられます）。管理設定なので信頼境界内ですが、`validate_limits` に上限（例 64 MiB）を設けるのが望ましいです。
- `is_fully_anchored` の偽陰性（非捕捉グループ）は K-3 で記載。

### K-9【低】その他

- **ACME キャッシュの一時ファイル**（[src/acme.rs:244-257](src/acme.rs#L244)）: `tokio::fs::write` で作成してから `chmod 0600` するため、極短時間だけ既定権限（0644 & umask）になります。ディレクトリは事前に 0700 に設定されるため他ユーザーからは到達できませんが、`OpenOptions::mode(0o600)` で作成するのが確実です。
- **installer**（[scripts/install.sh:251-261](scripts/install.sh#L251)）: `curl` に `--proto '=https'` がなく、`SHA256SUMS` を同じ配信元から取得して `tar -xzf` を root で実行します。リリースが侵害された場合の影響は大きいので、`--proto` 制限と `tar --no-same-owner`、可能なら署名検証（minisign/Sigstore）を推奨します。
- **`kunato upgrade`**（[src/upgrade.rs:48-71](src/upgrade.rs#L48)）: GitHub の `install.sh` を root で `sh` に渡す設計（`curl | sudo sh` と同等）は文書化済みですが、タグは可変なので「不変アセット」というコメントの前提は GitHub 側の仕様に依存します。
- **ログ量**: `rejected()` が 429/503/403 ごとに `warn!` を出します（[src/proxy/server.rs:724-732](src/proxy/server.rs#L724)）。グローバル上限 2000 rps の間は 1 リクエスト 1 行になり、I/O とディスクを圧迫します。レート制限された拒否はサンプリングまたは `debug` が望ましいです。
- **`x-forwarded-for` は上書き**（クライアント偽装不可）で正しい実装ですが、CDN/LB 配下では全クライアントが CDN の IP として扱われ、レート制限・バン・`source_ip` ルールが CDN 単位になります（文書化済みの将来課題）。

---

## 3. 確認できた良い実装（レビューで裏取りした点）

- リクエスト処理経路に `unwrap`/`expect`/`panic!` が無い（`unreachable!` は `parse_duration` の到達不能分岐のみ）。
- 正規表現はコンパイル時のみ、`size_limit`/`dfa_size_limit`、パターン長 4 KiB・64 個の上限。`regex` は線形時間で ReDoS 耐性あり。
- hop-by-hop ヘッダ除去、`Connection` トークン除去、`X-Forwarded-*` の上書き、legacy identity ヘッダ（`Forwarded`/`X-Real-IP`/`X-Client-IP`/`X-Forwarded-Port`)の削除。
- ALLOW の「全フォーム一致」ロジック（path forms、重複ヘッダ、cookie、body forms）は妥当（ただし K-3 のアンカー検証が前提）。
- 設定は parse → validate → compile の全か無か方式で、reload 失敗時は旧設定を保持。`ArcSwap` による原子的スワップ。
- ルール更新は HTTPS 限定（loopback 以外の http 禁止）、リダイレクトのダウングレード禁止・クロスホスト上限、SHA-256 検証、全体設定での再コンパイル後に原子的 rename。
- admin リスナは loopback 強制、接続数上限、ヘッダタイムアウト。
- ACME のドメイン検証（ワイルドカード/IP/ラベル長）、キャッシュ 0700/0600。
- タイムアウト（header/body/upstream/shutdown/websocket idle）、接続・リクエストのバウンド、HTTP/2 `max_concurrent_streams`、QUIC ストリーム上限。
- `cargo deny` のポリシー（advisories 無視なし、wildcards deny、未知レジストリ/ git 禁止）が適切。

---

## 4. 推奨対応順

1. **K-1**: デコード打ち切りの fail-closed 化（WAF としての検査保証に直結）
2. **K-2**: 検査メモリの合計上限（接続・プロセス単位）と既定 `max_body_bytes` の見直し
3. **K-3**: アンカー検証を AST ベースに置換（`regex-syntax` の `Hir` 利用）
4. **K-5 / K-6**: idle タイムアウトの導入、追跡テーブルの LRU 化
5. **K-4 / K-7 / K-8 / K-9**: 予算・完全性フラグ・検証上限・権限の改善

---

## 5. 検証できなかったこと

- `cargo fmt` / `cargo clippy --all-targets -- -D warnings` / `cargo deny check` / `cargo test` は、**サンドボックスが UNC ワークスペースの ACL を解決できずコマンド実行自体が失敗**したため未実行です。ユーザー環境（WSL 内）で実行し、特に K-1（`tests/proxy.rs` にデコード打ち切りのテストを追加）、K-3（`allow_*_must_be_anchored` に `^a|b$` を追加）の回帰テストを足すことを推奨します。
- 依存クレート（hyper 1.12 / h3 0.0.8 / quinn ほか）の既知脆弱性は、オフラインのため advisory DB 照合ができていません。`cargo deny check` と `cargo audit` の CI 実行を前提としてください。

ご希望であれば、K-1〜K-3 について実際のパッチ（テスト付き）を作成します。

---

## 6. 2026-11-01 レビュー指摘（27件）の修正可否検証

対象: `security_review/report_20261101_1.md`（Kunato 自身 12件・Origin 防御 15件）。全27件について報告書の `file:line` を実コードと突き合わせ、修正可否を検証した（コード変更なし・読み取りのみ。ベースラインの `cargo test` は成功）。

**結論: 27件すべて現行アーキテクチャの枠内で修正可能。** 「修正不能」は 0 件。ただし 17件は局所修正で完結するのに対し、10件は挙動・文書・既定値の変更かリリース基盤の整備を前提とする。

| 区分 | 件数 | 意味 |
|---|---|---|
| そのまま修正可能 | 17 | 局所的なコード修正で完結。設計判断不要 |
| 方針決定つきで修正可能 | 10 | 挙動・文書・既定値の変更、またはリリース基盤の整備が前提 |
| 修正不能 | 0 | — |

コード修正だけでは完結しないのは **SELF-12 の署名検証**のみ（リリース基盤の変更が必要）。オフライン鍵＋CI 署名という範囲では実現可能。

重大度欄は §7 の正誤表に基づく補正後の値で、補正のないものは報告どおり。

### 6.1 第1部: Kunato 自身（SELF）

| ID | 重大度（報告→補正） | 検証判定 | 修正可否 | 工数 | 要点 |
|---|---|---|---|---|---|
| SELF-01 | Critical | 妥当（保持期間の記述のみ一部誤り） | 条件付き | M（+L） | 64 MiB×4並列で枯渇は事実。`shrink_to` 追加で解消。下流書き込み期限だけは hyper に機構がなく新設定が必要 |
| SELF-02 | High | 妥当（前提条件の記載不足） | 可能 | M | 1シャード飽和には10万キー必要（IPv6 `/64` 併用なら現実的）。他シャードの idle 退避で最小修正可 |
| SELF-03 | High | 妥当（HTTP/3 は既定 off） | 可能 | S〜M | `remote_address_validated()`＋`retry()` で解決。報告案の「HS後にガード取得」は半開接続を無制限化する別の穴 |
| SELF-04 | High | 妥当 | 条件付き | M | 残量クランプ＋段階読みは機械的。メッセージ毎レート制限は正規チャット誤BANのため既定 off の新設定が安全 |
| SELF-05 | Medium | 一部妥当（watcher は `spawn_blocking`） | 可能 | M | O(N²) は事実。16 MiB 上限で有界、起動・validate も影響 |
| SELF-06 | Medium | 一部妥当 | 条件付き | M〜L | スピンは最大1秒。無限ループは state が永続的に書けない場合のみ。直列化は設計判断 |
| SELF-07 | Medium | 一部妥当（「直後に読めない」は誤り） | 可能 | S〜M | 条件は sudoers `umask=0077/0027`。`chown -R`＋モード継承で修正 |
| SELF-08 | Medium | 一部妥当 | 条件付き | S | 実害はログ/CPU 増幅（400 で上流には届かない）。解析順変更は docs と矛盾するポリシー変更 |
| SELF-09 | Medium | 妥当（注入は条件付き） | 可能 | M | 未クォート出力は事実。parser は quoted を既に読めるので producer 側のみ修正 |
| SELF-10 | Low | 一部妥当（TCP の記述が不正確） | 可能 | S | QUIC 共有のみ実害。`acme-tls/1` 単一要求化で修正（TCP 側は §7.1） |
| SELF-11 | Low | 一部妥当（admin の idle 欠落は誤り） | 可能 | S | `header_read_timeout` が keep-alive idle も切る。`ptr::eq` ガードで churn 解消（admin は §7.1） |
| SELF-12 | Low | 妥当（文書化済み TODO） | 条件付き | S＋L〜XL | `env_clear()` は S。署名は CI 署名・鍵運用・install.sh のブートストラップ設計が必要 |

### 6.2 第2部: Origin 防御のギャップ（ORIGIN）

| ID | 重大度（報告→補正） | 検証判定 | 修正可否 | 工数 | 要点 |
|---|---|---|---|---|---|
| ORIGIN-01 | High | 妥当（オリジン依存） | 可能 | M | `path_forms` 全段正規化で解消。報告の fix#2（ALLOW のアンカー必須化）は無効かつ prefix 用法を壊す |
| ORIGIN-02 | High → Medium | 一部妥当 | 条件付き | M | 不正境界のみなら既に `400`。成立は decoy 併用＋origin が last-wins のとき |
| ORIGIN-03 | High | 一部妥当 | 可能 | S | 重複 `Content-Type` 拒否は数行。`text/json` 拡張は任意 |
| ORIGIN-04 | High → Medium | 一部妥当（「自己矛盾」は誤り） | 条件付き | M | 宣言 type 優先は文書化・blackbox 固定済み。低 FP の署名 fallback は可能、不一致拒否は方針変更 |
| ORIGIN-05 | High | 一部妥当（バックスラッシュは誤り） | 可能 | M | `filename*` と PATCH は事実。`flatten_part` の `filename=` 出力＋ルールに PATCH 追加 |
| ORIGIN-06 | High | 妥当（+報告外の穴） | 可能 | S〜M | raw body 未走査は事実。`body_forms` の生成ゲートも併せて修正が必要 |
| ORIGIN-07 | Medium | 一部妥当 | 条件付き | M | マーカー追加は S。コメント上限は 4096 拡張では再バイパス、走査再設計が要る |
| ORIGIN-08 | Medium | 妥当 | 可能 | S | `\r` と `\"""` のレキサー差分。Parser 側に合わせるだけ |
| ORIGIN-09 | Medium | 妥当 | 可能 | M | part 単位処理へ置換。fail-closed 化を伴う |
| ORIGIN-10 | Medium | 妥当（末尾空白は過大） | 可能 | M | `form_decode` と multipart ヘルパの再利用で閉じる |
| ORIGIN-11 | Medium | 妥当 | 可能 | M | サイズ超過フェイルオープンは事実。形状判定＋重複キー拒否で修正 |
| ORIGIN-12 | Medium | 一部妥当 | 条件付き | M〜L | `decode_body: false` だけが原因ではない（Content-Type 欠落）。hot reload は docs の仕様変更 |
| ORIGIN-13 | Medium → Low | 一部妥当（「オリジンへ転送」は誤り） | 可能 | S〜M | 上流は h1 固定で `Trailer` 除去済み。実漏れは h2/h3 応答 trailer のみ→strip で足りる |
| ORIGIN-14 | Medium | 妥当（Shift_JIS は過大） | 条件付き | M | 415 拒否が現実的。トランスコードは新規依存＋全経路対応で XL |
| ORIGIN-15 | Medium | 一部妥当 | 可能 | M | SQLi・HPP・XSS・SSRF・`auth_path` は事実。JWT の「小文字 typ」は誤り（`(?i)` 済み） |

### 6.3 報告書側の誤り・誇張（修正時に騙されないための注意）

1. **SELF-01**: 「64 MiB を応答完了まで保持」は誤り。解放は上流応答ヘッド＋バッファリングまで（最大 `upstream_response` 30秒）。応答完了まで残るのは 3 MiB 側。
2. **SELF-11**: Admin の idle 制御欠落は誤り。`header_read_timeout(10s)` が keep-alive idle も切る。
3. **ORIGIN-02**: 「multipart 検査全体をバイパス」は過大。不正境界しか無ければ form guard が `400` で止める（fail-closed）。
4. **ORIGIN-04**: 「自己矛盾」は誤り。active type 宣言時の通過は `docs/development.md` と blackbox で固定された意図的挙動。
5. **ORIGIN-05**: `filename="\.htaccess"` は raw body の正規表現に一致する（`[^\r\n;]{0,512}` は `\` を含む）。
6. **ORIGIN-13**: リクエスト trailer はオリジンに届かない（上流 h1 固定＋`Trailer` hop-by-hop 除去）。hyper 側の上限（100個/16 KiB）もあり「制限なし」も不正確。
7. **ORIGIN-15**: JWT `none` の「小文字 `typ`」は `(?i)` で既に一致。正しいのは空白挿入（`{ "alg":"none"}`）によるバイパス。
8. **SELF-10**: TCP 側の `["h2","acme-tls/1"]` はサーバ優先順で `acme-tls/1` が交渉されるため指摘は不正確（実害は QUIC 共有のみ）。

### 6.4 修正の進め方（依存関係を考慮した3段階）

1. **第1波: リリース不要（ルールのみ）— 1〜2日**
   ORIGIN-15 の正規表現5件と ORIGIN-05 の `PATCH` 追加。`dist/rules.yaml` 再生成＋`scripts/check-rules-compat.sh`＋blackbox。ルール形式は不変なので旧バイナリでも受理される。
2. **第2波: 局所的なエンジン修正 — 約1〜2週間**
   ORIGIN-01/03/06/08/09/10/11/13、SELF-07/09/10/11。入力正規化・検証・展開の修正で、ほぼ既存ヘルパの再利用で閉じる。バイナリリリースが必要。
3. **第3波: DoS・供給網 — 約2〜3週間**
   SELF-01/02/03/04/06 と SELF-12。SELF-01 の書き込み期限と SELF-12 の署名基盤が最も重く、設定項目追加・CI 変更・鍵運用の決定を伴う。

**合計見積り: 約17〜20人日**（実装＋テスト＋docs）。SELF-12 の署名基盤まで含めると **+5〜10人日**。

### 6.5 検証方法と制約

- 全27件を6系統に分けて実コードと突き合わせ、各指摘について「再現条件」「修正可否」「修正方針（`file:line`）」「影響範囲」「工数」を確認した。コードは変更していない。
- ベースラインの `cargo test` は成功（exit 0）。修正時は AGENTS.md の必須チェック（`cargo fmt` / `clippy --all-targets -- -D warnings` / `scripts/check-deny.sh` / `cargo test`）に加え、ルール変更では `dist/rules.yaml` の再生成と互換ゲート、`docs/attack-coverage.md` の判定更新がセットになる。
- 前回の本レビュー K-1〜K-3 については、現行コードで fail-closed なデコード打ち切り（`413`/`415`/`400`）、プロセス全体の検査予算（256 MiB）、HIR ベースの ALLOW アンカー検証が入っていることを確認した。K-2 の残課題は本節 SELF-01 に対応する。

---

## 7. 2026-11-01 レビューの正誤表

方針: 原本（`security_review/report_20261101_1.md`）は診断記録として書き換えない。誤認・過大評価・補足は本節に記録し、重大度の補正は §6 に反映する。修正しない項目は「won't-fix」として理由を残し、次のレビューで同じ指摘が再発したときの判断材料にする。

### 7.1 事実誤認（実装は正しく、修正しない）

| ID | 報告の記述 | 実際（根拠） | 扱い |
|---|---|---|---|
| SELF-10 | TCP でも `["h2","acme-tls/1"]` の提示でチャレンジ証明書が返り RFC 8737 違反 | TCP はサーバ優先順で `acme-tls/1` が交渉され、直後に close する。実害は QUIC (`h3`) との共有のみ | QUIC 側だけ修正。TCP 側は won't-fix |
| SELF-11 | `AdminServer` は shutdown を監視せず keep-alive のアイドル制御もない | `header_read_timeout(10s)` が keep-alive idle も切る。`run` は drain（5秒）後に abort する | admin は won't-fix。`client_for` の churn のみ修正 |
| ORIGIN-05 | 引用符内バックスラッシュ `filename="\.htaccess"` は raw/flatten とも一致しない | `[^\r\n;]{0,512}` は `\` を含むため raw body で一致する | 当該手法は won't-fix。`filename*` と PATCH は修正 |
| ORIGIN-13 | Trailer がヘッダ制限・ルール評価をバイパスして**オリジンへ転送**される | 上流は h1 固定で `Trailer` は hop-by-hop 除去され届かない。hyper の h1 trailer 上限（100個/16 KiB）もある | 下流 h2/h3 応答 trailer の strip のみ実装 |

### 7.2 過大評価（重大度を補正して修正する）

| ID | 報告 | 補正 | 根拠 |
|---|---|---|---|
| SELF-01 | 64 MiB の予約を**応答完了まで**保持 | Critical 据え置き（保持期間のみ訂正） | 解放は上流応答ヘッド＋バッファリングまで。応答完了まで残るのは 3 MiB 側 |
| ORIGIN-02 | multipart 検査**全体**をバイパス可能 | High → Medium | 不正境界しか無ければ form guard が `400`。成立は有効な decoy 併用＋origin が last-wins のとき |
| ORIGIN-04 | 宣言 type 優先ロジックが**自己矛盾** | High → Medium | active type 宣言時の通過は文書化・blackbox 固定済み。残る実ギャップは未検証 safe type の署名スキップ |
| ORIGIN-10 | 先頭・**末尾**の空白でリダイレクト検査を回避 | Medium 据え置き | 末尾は `starts_with` に影響せず検出は成立。回避できるのは先頭・内部の空白と制御文字 |
| ORIGIN-15 | JWT `none` が**小文字 `typ`** でバイパス | Medium 据え置き | `(?i)` により一致する。有効なのは空白挿入（`{ "alg":"none"}`）によるバイパス |

### 7.3 補足（重大度は据え置き、再現条件として明記）

| ID | 補足する前提 |
|---|---|
| SELF-02 | 1シャード飽和には10万キーを600秒以内に維持する必要がある（IPv6 `/64` 併用で現実的） |
| SELF-03 | HTTP/3 は既定 off。有効化している構成でのみ成立する |
| ORIGIN-01 | 成立は origin のドットセグメント解決順序に依存する（`%2f` を区切りにしない実装で有効） |

### 7.4 再発防止

- **再現テスト先行**: 修正着手時に再現テストを先に書く。再現しない指摘は修正せず 7.1 に追加する。
- **文書との整合**: ORIGIN-02 に関連して `docs/attack-coverage.md` の Multipart Boundary Abuse が実装より強い主張になっていないか確認し、必要なら実装か文書のどちらかを直す。
- **レビュー工程**: 次回以降も §6 の修正可否検証を必須工程とし、重大度は本節の補正を経て確定する。
---

## 8. 実施状況（2026-11-01）

§6.4 の第1波・第2波を実装し、テストと black-box で確認した。

### 8.1 第1波（ルールのみ、リリース不要）

- 対象: ORIGIN-15 の正規表現5件（SQLi の括弧・コメント、HPP の介在パラメータ／ネスト JSON、XSS のイベントハンドラ、SSRF の userinfo・末尾ドット、JWT `none` の空白挿入）と、ORIGIN-05 の `malicious-upload` への `PATCH` 追加。
- `dist/rules.yaml` を再生成し、`scripts/blackbox-test.sh` を実行。**BLOCK 2,084 件・ALLOW 591 件すべて通過、失敗 0**。ルール形式は不変のため旧バイナリでも受理される。
- コミット: `Cover parenthesized SQLi and PATCH uploads in the bundled rules`。

### 8.2 第2波（エンジン修正）

- ORIGIN-01: `path_forms` が全デコード段階を正規化。`%252f` + `..` で `ALLOW`/`content_routes` を迂回できない。
- ORIGIN-03: 重複 `Content-Type` を `400` で拒否。
- ORIGIN-05: `flatten_part` が `filename="..."` を出力し、RFC 5987 の percent エンコード名がルールに一致する。
- ORIGIN-06/10: SSRF が raw body と全 URL を走査。重複・リダイレクト検査が `+` をデコードし、ネスト JSON と multipart を走査。リダイレクトは制御文字・先頭空白・`\` を正規化。
- ORIGIN-08/09: GraphQL のイントロスペクションスキャナをレキサーに一致（`\r` コメント、`\"""`）。multipart は part 単位で解析し、バイナリ添付が `operations` を隠さない。
- ORIGIN-11: JWT はサイズ超過の JWT 形状トークンをフェイルクローズ、重複ヘッダキーを拒否、タブ区切りとエンコード Cookie を検査。
- ORIGIN-13: trailer フレームを両方向で破棄（未検査のまま転送しない）。
- ORIGIN-15（engine 側）: `auth_path_matches` がマトリックスパラメータを除去。
- SELF-07: `write_atomic` が置換前ファイルの所有者・モードを引き継ぎ、installer は state ディレクトリ全体を `kunato` に渡す。
- SELF-09: ログのテキストフィールドを必要時に引用・エスケープ（`\xNN` を含む）。parser は両形式を読め、Raw 出力は制御文字を無害化。
- SELF-10: ACME リゾルバは `acme-tls/1` が単独提示されたときだけチャレンジ証明書を返す。
- SELF-11: reload 前のスナップショットを持つリクエストは upstream client を再生成しない。
- 検証: `cargo fmt` / `cargo clippy --all-targets -- -D warnings` / `./scripts/check-deny.sh` / `cargo test`（659 unit + 統合）すべて成功。black-box も上記のとおり通過。
- コミット: `Close the origin-defense gaps found in the security review`。

### 8.3 残り

- 第3波: SELF-01（検査予算の縮小・書き込み期限）、SELF-02（シャード退避）、SELF-03（QUIC Retry）、SELF-04（WebSocket 課金）、SELF-06（更新ループ直列化）、SELF-12（署名基盤）。
- 条件付き（方針決定が必要）: ORIGIN-02、ORIGIN-04、ORIGIN-07、ORIGIN-12、ORIGIN-14。
- 未割当: SELF-05（YAML パーサの位置追跡）。
