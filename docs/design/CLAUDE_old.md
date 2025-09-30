# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 開発環境

### Dev Container環境
このプロジェクトは`.devcontainer`設定を含んでおり、VS CodeまたはGitHub Codespacesで統一された開発環境を提供します。

#### Dev Container構成
- **ベースイメージ**: mcr.microsoft.com/devcontainers/go:1-1.23-bookworm
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

#### 作業ディレクトリ
- コンテナ内の作業ディレクトリは `/workspace`
- すべてのコマンドは `/workspace` から実行
- ソースコードは `/workspace` 直下に自動マウント

## 開発コマンド

このプロジェクトでは、`go-task`（Taskfile.yml）を使用してビルドとタスク管理を行います。

### go-taskの使用

```bash
# 利用可能なタスク一覧を表示
task --list
# または
task

# 主要なタスク
task build           # バイナリをビルド
task build-all       # 全プラットフォーム向けビルド
task test            # テスト実行
task test-coverage   # カバレッジ付きテスト
task lint            # リント実行
task fmt             # コードフォーマット
task check           # 全品質チェック実行
task clean           # ビルド成果物をクリーン
```

### ビルド
```bash
# 単一プラットフォーム用バイナリをビルド
task build

# 複数プラットフォーム用バイナリをビルド（Linux, macOS Intel/ARM, Windows）
task build-all

# ビルド成果物をクリーン
task clean
```

### テスト
```bash
# 全テストを実行
task test

# カバレッジ付きでテストを実行
task test-coverage

# レース条件検出付きテスト
task test-race

# 短時間テストのみ
task test-short

# 特定パッケージのテスト
task test-pkg PKG=pkg/sysdig

# ベンチマークテスト
task bench
```

### 開発ツール
```bash
# コードのリント（要golangci-lint）
task lint
# 自動修正可能な問題を修正
task lint-fix

# 静的解析
task staticcheck

# コードフォーマット
task fmt

# go vetを実行
task vet

# 全品質チェック（fmt, vet, staticcheck, lint, test）
task check

# 依存関係の管理
task deps          # download, tidy, verify
task deps-update   # 依存関係を更新
task deps-graph    # 依存関係グラフを表示
task list-outdated # 古い依存関係をリスト
```

### 便利なタスク
```bash
# TODO/FIXMEコメントを検索
task todo

# セキュリティチェック（要gosec）
task sec-check

# importを整理（要goimports）
task imports

# 循環的複雑度をチェック（要gocyclo）
task complexity

# 開発モード - ファイル監視と自動ビルド（要fswatch）
task dev-watch

# リリース用ビルド（テスト、リント後に全プラットフォーム向けビルド）
task release

# CI環境用タスク
task ci

# コミット前チェック
task pre-commit

# APIドキュメント生成
task docs

# バージョン情報表示
task version
```

### デバッグ
```bash
# delveデバッガでデバッグ実行
dlv debug cmd/sysdig-vuls/main.go -- -token YOUR_TOKEN -command list

# テストのデバッグ
dlv test ./pkg/sysdig

# VS Codeデバッグ（.vscode/launch.json設定済み）
# F5キーでデバッグ開始
```

### アプリケーション実行
```bash
# ビルドして実行
task run

# 脆弱性リストを取得して実行（環境変数を使用）
task run-list

# デバッグモードで実行
task run-debug

# または直接実行（APIトークンが必要）
./bin/sysdig-vuls -token YOUR_TOKEN -command list
```

### Runtime制限機能
Runtime結果の取得では、asset.type別に取得件数を制限できます。大量のworkloadデータを効率的に処理するための機能です。

#### デフォルト制限
```bash
# デフォルト設定（推奨）
./bin/sysdig-vuls -command runtime
./bin/sysdig-vuls -command runtime-cache -days 7 -cache runtime.db

# デフォルト制限値：
# - workload: 300件（大量データを制限）
# - host: 無制限（通常数十件）
# - container: 無制限（通常数十件）
```

#### カスタム制限
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

#### SQLiteでのasset.type別分析
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

## アーキテクチャ概要

このツールはSysdig Secure APIと連携してコンテナ環境の脆弱性を管理するCLIツール兼Goライブラリです。

### パッケージ構造

1. **cmd/sysdig-vuls/main.go**
   - CLIエントリポイント
   - コマンド解析とルーティング（list、get、update）
   - 設定優先順位：CLIフラグ > 設定ファイル > 環境変数 > デフォルト値

2. **pkg/sysdig/client.go**
   - Sysdig APIクライアント実装
   - HTTPクライアント（30秒タイムアウト）
   - Bearer認証使用
   - エンドポイント：`/api/secure/v1/vulnerabilities`
   - メソッド：
     - `ListVulnerabilities()`: 全脆弱性取得
     - `GetVulnerability(id)`: 特定脆弱性取得
     - `UpdateVulnerability(id, updates)`: 脆弱性更新
     - `ListVulnerabilitiesByPackage(name)`: パッケージ別フィルタ
     - `ListVulnerabilitiesBySeverity(level)`: 重要度別フィルタ

3. **pkg/config/config.go**
   - 設定管理（JSON形式）
   - 環境変数サポート：`SYSDIG_API_TOKEN`、`SYSDIG_API_URL`
   - デフォルトURL：`https://us2.app.sysdig.com`

### API統合パターン

- すべてのAPI呼び出しは`makeRequest()`メソッドを通じて実行
- レスポンスは`VulnerabilityResponse`構造体にデコード
- エラーハンドリング：404は特別処理、その他はHTTPステータス付きエラー

### 主要データ構造

`Vulnerability`構造体には以下のフィールドが含まれる：
- ID、CVE番号、重要度、ステータス
- 説明、影響を受けるパッケージリスト
- CVSSスコア、ベクトル
- 公開日時、更新日時
- メタデータ（汎用マップ）

## APIドキュメント

このツールはSysdig Secure APIをベースにしています。詳細なAPIドキュメントは以下を参照してください：

- **Sysdig APIドキュメント**: https://us2.app.sysdig.com/apidocs/secure?_product=SDS
- **Swagger UI**: https://us2.app.sysdig.com/secure/swagger.html

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

## 注意事項

- Go 1.23を使用（go.modで指定）
- APIトークンは必須（取得先：Sysdig UIの設定画面）
- 現在サポートしているリージョン：US2（デフォルト）、US3、EU1、AU1