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

### ビルド
```bash
# 単一プラットフォーム用バイナリをビルド
make build

# 複数プラットフォーム用バイナリをビルド（Linux, macOS Intel/ARM, Windows）
make build-all

# ビルド成果物をクリーン
make clean
```

### テスト
```bash
# 全テストを実行
make test
# または直接Goコマンドで
go test ./...

# カバレッジ付きでテストを実行
make test-coverage
# または直接Goコマンドで
go test -v -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html

# 特定パッケージのテスト
go test -v ./pkg/sysdig
go test -v ./pkg/config

# ベンチマークテスト
go test -bench=. ./...
```

### 開発ツール
```bash
# コードのリント（要golangci-lint）
make lint
# または直接実行
golangci-lint run

# 静的解析
staticcheck ./...

# コードフォーマット
make fmt
# または直接実行
go fmt ./...
gofmt -s -w .

# 依存関係の管理
make deps
# または直接実行
go mod tidy
go mod download
go mod verify
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
make run

# または直接実行（APIトークンが必要）
./bin/sysdig-vuls -token YOUR_TOKEN -command list
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