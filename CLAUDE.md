# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## プロジェクト概要

SysdigのクラウドベースRCE（ランタイムコンテナセキュリティ）が検出した脆弱性を管理するためのGolang製CLIツール＆ライブラリ。Sysdig V2 APIを使用して、パイプラインスキャン結果とランタイムスキャン結果から脆弱性データを取得・キャッシュし、SQLiteデータベースで管理する。

## 推奨実行フロー

### 標準的な脆弱性データ取得

```bash
# scripts/fetch_vulnerabilities.shを使用（推奨）
./scripts/fetch_vulnerabilities.sh [日数] [バッチサイズ] [API遅延秒数]

# またはパフォーマンスレベル指定（1-30）
./scripts/fetch_vulnerabilities.sh [日数] perf [レベル]

# デフォルト設定で実行（7日間、バッチ2、遅延3秒）
./scripts/fetch_vulnerabilities.sh
```

**スクリプトの自動処理:**
1. バイナリの自動ビルド（未ビルドの場合）
2. パイプラインスキャン結果の並列取得
3. ランタイムスキャン結果の並列取得
4. タイムスタンプ付きディレクトリにデータベース保存
5. 処理ログの自動記録

**パフォーマンスレベルの目安:**
- レベル1-5: 安全重視（Rate limit回避優先）
- レベル10-15: バランス型（デフォルト推奨）
- レベル20-30: 速度重視（Rate limitリスク有り）

### 生成されるファイル

```
data/YYYYMMDD_HHMMSS/
  ├── pipeline_vulnerabilities.db  # パイプラインスキャン結果
  ├── runtime_vulnerabilities.db   # ランタイムスキャン結果
  └── report.md                    # 分析レポート（手動生成）

/tmp/
  ├── pipeline_YYYYMMDD_HHMMSS.log # パイプライン取得ログ
  └── runtime_YYYYMMDD_HHMMSS.log  # ランタイム取得ログ
```

## ビルドとテストコマンド

このプロジェクトは**Task**（Taskfile.yml）を使用して開発タスクを管理している。

### タスク一覧の表示

```bash
# 利用可能なタスク一覧を表示
task --list
# または
task
```

### 主要コマンド

```bash
# ビルド
task build                    # 現在のプラットフォーム向けビルド（bin/sysdig-vulsを生成）
task build-all               # 複数プラットフォーム向けビルド
task clean                   # ビルド成果物をクリーン

# テスト
task test                    # 全テスト実行
task test-coverage           # カバレッジ付きテスト（coverage.htmlを生成）
task test-race               # レース条件検出付きテスト
task test-short              # 短時間テストのみ
task test-pkg PKG=pkg/sysdig # 特定パッケージのみテスト
task bench                   # ベンチマークテスト

# コード品質
task lint                    # golangci-lintでリント
task lint-fix                # 自動修正可能なリント問題を修正
task fmt                     # コードフォーマット
task vet                     # go vetを実行
task staticcheck             # staticcheckを実行
task check                   # 全品質チェック（fmt, vet, staticcheck, lint, test）

# 依存関係
task deps                    # 依存関係の管理（download, tidy, verify）
task deps-update             # 依存関係の更新
task deps-graph              # 依存関係グラフを表示
task list-outdated           # 古い依存関係をリスト

# 実行
task run                     # ビルドして実行
task run-list                # 脆弱性リスト取得（SYSDIG_API_TOKEN必須）
task run-debug               # デバッグモードで実行

# リリース・CI
task release                 # リリース用ビルド（テスト、リント後に全プラットフォーム向けビルド）
task ci                      # CI環境用タスク
task pre-commit              # コミット前チェック

# 便利なツール
task todo                    # TODO/FIXMEコメントを検索
task sec-check               # セキュリティチェック（要gosec）
task imports                 # importを整理（要goimports）
task complexity              # 循環的複雑度をチェック（要gocyclo）
task dev-watch               # ファイル監視と自動ビルド（要fswatch）
task docs                    # APIドキュメント生成
task version                 # バージョン情報表示
```

## コードアーキテクチャ

### パッケージ構造

- **`cmd/sysdig-vuls/`**: CLIアプリケーションのエントリポイント（main.go）
  - コマンドパース、実行フロー制御、出力フォーマット選択
  - サポートコマンド: list, filter, get, summary, cache, pipeline, runtime, pipeline-cache, runtime-cache, scan-details, accepted-risks
- **`pkg/sysdig/`**: Sysdig V2 APIクライアント実装（client.go）
  - すべてのAPI呼び出しは`makeRequest()`メソッドを経由
  - V2 API構造体（Vulnerability, VulnV2, PackageV2）を使用
  - `FixedInVersion`がnullの場合は`Fixable=false`と自動判定
- **`pkg/config/`**: 設定管理（config.go）
  - 優先順位: CLIフラグ > 設定ファイル > 環境変数 > デフォルト値
- **`pkg/cache/`**: SQLiteキャッシュ実装（cache.go）
  - 脆弱性データと詳細なスキャン結果をローカルに保存
  - `scan_results`, `scan_vulnerabilities`テーブルでリレーショナル管理
- **`pkg/output/`**: テーブル形式出力（table.go）
  - table, detailed, summary, aws形式の出力をサポート

### V2 API設計の重要ポイント

1. **エンドポイント判定**:
   - `/api/`プレフィックス → 元のbaseURL（us2.app.sysdig.com）を使用
   - それ以外 → api.us2.sysdig.com に変換してV1エンドポイントを構築
   - タイムアウト無効化（`Timeout: 0`）で長時間API呼び出しに対応

2. **Fixableステータス判定**:
   - V2 APIでは`FixedInVersion`フィールドがポインタ型（`*string`）
   - `null`の場合は修正不可能、値が存在する場合は修正可能
   - `Vuln.Fixable`フィールドは計算値（JSONマッピング時に自動設定）

3. **並行API呼び出しとレート制限対応**:
   - pipeline-cache/runtime-cacheコマンドで並行処理を実装
   - バッチサイズ（デフォルト2）とAPIディレイ（デフォルト3秒）で制御
   - レート制限エラー時は最大3回リトライ、待機時間は`apiDelay*2`秒

### SQLiteキャッシュスキーマ

- **`scan_results`テーブル**: スキャン結果のメタデータ（result_id, scan_type, AWS情報、脆弱性カウント）
- **`scan_vulnerabilities`テーブル**: 各スキャン結果に紐づく詳細な脆弱性情報
- パイプラインとランタイムのデータを同一DBで管理、`scan_type`で区別

## 開発ワークフロー

### DevContainer環境

このプロジェクトは`.devcontainer`設定を含んでおり、VS CodeまたはGitHub Codespacesで統一された開発環境を提供します。

#### 環境構成
- **ベースイメージ**: mcr.microsoft.com/devcontainers/go:1-1.23-bookworm
- **作業ディレクトリ**: `/workspace`
- **開発ツール**: golangci-lint、delve、gopls、staticcheck等がプリインストール
- **VS Code拡張**: Go、Docker、GitLens、GitHub Copilot等が自動設定
- **GitHub CLI**: PR作成・管理用にgh CLIを統合
- **Docker-in-Docker**: コンテナ内でDockerコマンド実行可能

#### 環境変数設定
`.devcontainer/.env.example`をコピーして`.devcontainer/.env`を作成し、必要な環境変数を設定：
```bash
cp .devcontainer/.env.example .devcontainer/.env
# SYSDIG_API_TOKENとSYSDIG_API_URLを設定
```

#### 起動時の自動処理
- コンテナ起動時に`go mod download`が自動実行
- ソースコードは `/workspace` 直下に自動マウント
- すべてのコマンドは `/workspace` から実行

### 新機能追加時の手順

1. **APIメソッド追加**: `pkg/sysdig/client.go`に新しいメソッドを追加
2. **CLIコマンド追加**: `cmd/sysdig-vuls/main.go`のswitchケースに追加
3. **テスト追加**: `pkg/sysdig/client_test.go`にユニットテストを追加
4. **品質チェック**: `task check`で全チェックを実行
5. **ドキュメント更新**: README.mdとこのCLAUDE.mdを更新

### エラーハンドリングパターン

- 404エラー: 特別に処理（リソースが見つからない場合）
- その他のHTTPエラー: ステータスコード付きでエラーを返す
- レート制限エラー: リトライロジックで自動対応

## 環境変数

- `SYSDIG_API_TOKEN`: APIトークン（必須）
- `SYSDIG_API_URL`: APIベースURL（デフォルト: https://us2.app.sysdig.com）
- `CACHE_DIR`: キャッシュディレクトリ（デフォルト: /workspace/data）
- `CACHE_TYPE`: キャッシュタイプ（sqlite/csv）

## Runtime制限機能

Runtime結果の取得では、asset.type別に取得件数を制限できます。大量のworkloadデータを効率的に処理するための機能です。

### デフォルト制限
```bash
# デフォルト設定（推奨）
./bin/sysdig-vuls -command runtime
./bin/sysdig-vuls -command runtime-cache -days 7 -cache runtime.db

# デフォルト制限値：
# - workload: 300件（大量データを制限）
# - host: 無制限（通常数十件）
# - container: 無制限（通常数十件）
```

### カスタム制限
```bash
# 制限をカスタマイズ
./bin/sysdig-vuls -command runtime \
  -runtime-workload-limit 100 \
  -runtime-host-limit 20 \
  -runtime-container-limit 10

# 制限を無効化（0 = 無制限、内部的に10,000件まで）
./bin/sysdig-vuls -command runtime \
  -runtime-workload-limit 0 \
  -runtime-host-limit 0 \
  -runtime-container-limit 0

# 特定タイプをスキップ（負の値）
./bin/sysdig-vuls -command runtime \
  -runtime-workload-limit 500 \
  -runtime-host-limit -1 \
  -runtime-container-limit -1
```

### SQLiteでのasset.type別分析
```sql
-- asset.type別の脆弱性集計
SELECT asset_type,
       COUNT(*) as total_scans,
       SUM(critical_count) as total_critical,
       SUM(high_count) as total_high,
       SUM(medium_count) as total_medium,
       SUM(low_count) as total_low
FROM scan_results
WHERE scan_type = 'runtime'
GROUP BY asset_type
ORDER BY total_critical DESC, total_high DESC;

-- 特定asset.typeの詳細レポート
SELECT result_id, asset_type, pull_string,
       critical_count, high_count,
       aws_account_name, cluster_name
FROM scan_results
WHERE scan_type = 'runtime'
  AND asset_type = 'workload'
  AND (critical_count > 0 OR high_count > 0)
ORDER BY critical_count DESC, high_count DESC;
```

## 言語とコメント規約

- ドキュメントは**日本語**で記述
- コード内のコメントは**日本語**で記述
- gitコミットメッセージは**日本語**で記述

## デバッグ方法

```bash
# delveデバッガでCLIをデバッグ
dlv debug cmd/sysdig-vuls/main.go -- -token YOUR_TOKEN -command list -result-id RESULT_ID

# 特定パッケージのテストをデバッグ
dlv test ./pkg/sysdig

# VS Codeデバッグ（.vscode/launch.json設定済み）
# F5キーでデバッグ開始
```

## グローバルカスタムコマンド

以下のGit操作コマンドがグローバルに定義されています（~/.claude/commands）：

### /git:sync
mainブランチに切り替えて最新の変更をプルします。
```bash
# 使用方法
/git:sync
```

### /git:pr
Git差分を元にコミット、新しいブランチ作成、プッシュ、PR作成を自動化します。
```bash
# 使用方法
/git:pr "PRタイトル"
```

## APIドキュメント

このツールはSysdig Secure APIをベースにしています。詳細なAPIドキュメントは以下を参照してください：

- **Sysdig APIドキュメント**: https://us2.app.sysdig.com/apidocs/secure?_product=SDS
- **Swagger UI**: https://us2.app.sysdig.com/secure/swagger.html

## 注意事項

- Go 1.23を使用（go.modで指定）
- APIトークンは必須（取得先：Sysdig UIの設定画面）
- 現在サポートしているリージョン：US2（デフォルト）、US3、EU1、AU1

## データベース分析例

### 重要度別脆弱性集計

```sql
SELECT
  CASE
    WHEN severity_value = 4 THEN 'Critical'
    WHEN severity_value = 3 THEN 'High'
    WHEN severity_value = 2 THEN 'Medium'
    ELSE 'Low'
  END as severity,
  COUNT(*) as total,
  SUM(CASE WHEN fixable = 1 THEN 1 ELSE 0 END) as fixable,
  SUM(CASE WHEN exploitable = 1 THEN 1 ELSE 0 END) as exploitable
FROM scan_vulnerabilities
GROUP BY severity_value
ORDER BY severity_value DESC;
```

### 最も脆弱性が多いイメージ

```sql
SELECT
  pull_string,
  COUNT(*) as vuln_count,
  SUM(CASE WHEN severity_value >= 3 THEN 1 ELSE 0 END) as high_critical
FROM scan_results
WHERE scan_type = 'pipeline'
GROUP BY pull_string
ORDER BY high_critical DESC, vuln_count DESC
LIMIT 10;
```

### asset.type別の脆弱性分布

```sql
SELECT
  asset_type,
  COUNT(*) as total_scans,
  SUM(critical_count) as total_critical,
  SUM(high_count) as total_high
FROM scan_results
WHERE scan_type = 'runtime'
GROUP BY asset_type
ORDER BY total_critical DESC;
```

## 参考ファイル

- **scripts/fetch_vulnerabilities.sh**: 脆弱性データ取得の標準スクリプト
- **Taskfile.yml**: 全開発コマンドの定義
- **.cursor/rules/project.mdc**: Cursor用のプロジェクトルール
- **data/YYYYMMDD_HHMMSS/report.md**: 生成された分析レポート例