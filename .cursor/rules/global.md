# Cursor Rules for sysdig-vuls-utils

このプロジェクトはSysdig脆弱性管理APIツールセットです。以下のガイドラインに従って開発を行ってください。

## 言語設定
- ドキュメントは日本語で記述する
- コード内のコメントは日本語で記述する
- gitコミットメッセージは日本語で記述する

## プロジェクト概要
SysdigのクラウドベースRCE（ランタイムコンテナセキュリティ）が検出した脆弱性を管理するためのGolang製CLIツール＆ライブラリ。

## DevContainer環境での開発

### 作業ディレクトリ
- コンテナ内の作業ディレクトリ: `/workspace`
- プロジェクトのソースコードは `/workspace` 直下に配置される
- すべてのコマンドは `/workspace` から実行される

### DevContainer内でのGoコマンド実行
```bash
# ビルド（/workspaceから実行）
cd /workspace
go build -o bin/sysdig-vuls cmd/sysdig-vuls/main.go

# テスト実行
cd /workspace
go test ./...
go test -v ./pkg/...

# 特定パッケージのテスト
go test -v ./pkg/sysdig
go test -v ./pkg/config

# カバレッジ付きテスト
go test -v -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html

# ベンチマークテスト
go test -bench=. ./...

# 依存関係の管理
go mod tidy
go mod download
go mod verify

# コードフォーマット
go fmt ./...
gofmt -s -w .

# 静的解析
golangci-lint run
staticcheck ./...
```

### DevContainerでの開発フロー
1. VS Codeで「Reopen in Container」を実行
2. コンテナが起動すると自動的に `/workspace` に移動
3. `go mod download` と `make deps` が自動実行される
4. ターミナルから直接Goコマンドやmakeコマンドを実行可能

## アーキテクチャとコード規約

### パッケージ構造
- `cmd/sysdig-vuls/`: CLIアプリケーションのエントリポイント
- `pkg/sysdig/`: Sysdig APIクライアント実装
- `pkg/config/`: 設定管理ロジック

### コード実装時の注意
1. **API呼び出し**: すべてのAPI呼び出しは`pkg/sysdig/client.go`の`makeRequest()`メソッドを通じて実行する
2. **エラーハンドリング**: 404エラーは特別に処理し、その他はHTTPステータス付きでエラーを返す
3. **設定優先順位**: CLIフラグ > 設定ファイル > 環境変数 > デフォルト値の順で適用
4. **タイムアウト**: HTTPクライアントのタイムアウトは30秒に設定

## 開発コマンド

### よく使うコマンド
```bash
# ビルド
make build           # 単一プラットフォーム用
make build-all      # 全プラットフォーム用

# テスト
make test           # 全テスト実行
make test-coverage  # カバレッジ付きテスト

# 品質チェック
make lint           # golangci-lintでリント
make fmt            # コードフォーマット

# 実行
make run            # ビルドして実行
./bin/sysdig-vuls -token YOUR_TOKEN -command list
```

## API統合

### Sysdig API エンドポイント
- ベースURL: `https://us2.app.sysdig.com/api/secure/v1`
- 認証: Bearer トークン（ヘッダー: `Authorization: Bearer <token>`）

### 主要エンドポイント
- `GET /vulnerabilities` - 全脆弱性一覧
- `GET /vulnerabilities/{id}` - 特定脆弱性詳細
- `PATCH /vulnerabilities/{id}` - 脆弱性更新
- `GET /vulnerabilities?severity={level}` - 重要度フィルタ
- `GET /vulnerabilities?package={name}` - パッケージフィルタ

## データ構造

### Vulnerability構造体
```go
type Vulnerability struct {
    ID          string   // 脆弱性ID
    CVE         string   // CVE番号
    Severity    string   // 重要度 (critical/high/medium/low)
    Status      string   // ステータス
    Description string   // 説明
    Packages    []string // 影響パッケージ
    Score       float64  // CVSSスコア
    Vector      string   // CVSSベクトル
    PublishedAt string   // 公開日時
    UpdatedAt   string   // 更新日時
    Metadata    map[string]interface{} // メタデータ
}
```

## 環境変数
- `SYSDIG_API_TOKEN`: APIトークン（必須）
- `SYSDIG_API_URL`: APIベースURL（デフォルト: https://us2.app.sysdig.com）

## リージョン別エンドポイント
- 米国東部（デフォルト）: `https://us2.app.sysdig.com`
- 米国西部: `https://us3.app.sysdig.com`
- EU: `https://eu1.app.sysdig.com`
- アジア太平洋: `https://au1.app.sysdig.com`

## コード変更時のガイドライン

1. **新機能追加時**
   - `pkg/sysdig/client.go`にAPIメソッドを追加
   - `cmd/sysdig-vuls/main.go`にCLIコマンドを追加
   - 適切なエラーハンドリングを実装

2. **テスト追加**
   - 新しい機能には必ずユニットテストを追加
   - `make test`で全テストが通ることを確認

3. **ドキュメント更新**
   - README.mdの使用例を更新
   - CLAUDE.mdのアーキテクチャ情報を更新

## デバッグのヒント

### DevContainer内でのデバッグ
```bash
# delveデバッガを使用したデバッグ
cd /workspace
dlv debug cmd/sysdig-vuls/main.go -- -token YOUR_TOKEN -command list

# テスト時のデバッグ
dlv test ./pkg/sysdig

# ブレークポイントの設定例
(dlv) break main.main
(dlv) break pkg/sysdig.(*Client).ListVulnerabilities
(dlv) continue
(dlv) print vulnResp
```

### VSCode統合デバッグ
DevContainer環境では、VSCodeのデバッグ機能が自動設定されています：
1. 左サイドバーの「Run and Debug」を開く
2. 「create a launch.json file」をクリック
3. 「Go」を選択
4. F5でデバッグ開始

### ログ出力の追加
- API呼び出しの詳細を確認したい場合は、`pkg/sysdig/client.go`の`makeRequest()`にログを追加
- レスポンスボディを確認する場合は、エラー処理部分でbodyを出力
```go
// デバッグ用ログの例
log.Printf("API Request: %s %s", method, url)
log.Printf("Response Status: %d", resp.StatusCode)
```

## セキュリティ注意事項
- APIトークンをコードにハードコードしない
- 設定ファイルのパーミッションは600に設定（`config.Save()`で自動設定）
- APIトークンは環境変数か設定ファイルで管理

## グローバルカスタムコマンド

### Git操作コマンド（~/.claude/commands）
```bash
# mainブランチと同期（最新をプル）
/git:sync

# PR作成ワークフロー（コミット→ブランチ作成→プッシュ→PR作成）
/git:pr "PRのタイトル"

# 他のGitコマンドも利用可能
/git:push-head  # 現在のHEADをリモートにプッシュ
/git:rebase     # コミット履歴をリベース
```

これらのコマンドは`~/.claude/commands/`にグローバル定義されており、すべてのプロジェクトで利用可能。