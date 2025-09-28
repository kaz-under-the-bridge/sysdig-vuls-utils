# sysdig-vuls-utils

**Sysdig脆弱性管理APIツールセット**

SysdigのクラウドベースRCE（ランタイムコンテナセキュリティ）が検出した脆弱性を管理するためのGolang製コマンドラインツール＆ライブラリです。Sysdig Cloud環境における脆弱性の一覧取得、詳細情報の取得、ステータス更新などが可能です。

## 機能

- **脆弱性一覧の取得**: Sysdig環境内のすべての脆弱性を取得
- **脆弱性詳細の取得**: 特定の脆弱性の詳細情報を取得
- **脆弱性の更新**: 脆弱性のステータスやメタデータを変更
- **重要度でフィルタリング**: 重要度レベル（critical、high、medium、low）で脆弱性を検索
- **パッケージでフィルタリング**: 特定のパッケージに影響する脆弱性を検索
- **設定管理**: 設定ファイル、環境変数、CLIフラグをサポート
- **JSON出力**: 他のツールとの統合に適した機械可読な出力形式

## インストール

### 前提条件

- Go 1.23以降
- 有効なSysdig APIトークン

### Dev Container (VS Code/GitHub Codespaces)

このプロジェクトはDev Containerをサポートしています。VS CodeやGitHub Codespacesで簡単に開発環境を構築できます。

#### VS Codeで使用する場合

1. Docker DesktopとVS Code Dev Containers拡張をインストール
2. プロジェクトをVS Codeで開く
3. コマンドパレット（F1）から「Dev Containers: Reopen in Container」を選択
4. 自動的に開発環境が構築されます

#### GitHub Codespacesで使用する場合

1. GitHubリポジトリページで「Code」→「Codespaces」→「Create codespace on main」をクリック
2. 自動的にクラウド上に開発環境が構築されます

#### Dev Container環境の特徴

- Go 1.23開発環境（Microsoft Dev Containersベース）
- golangci-lint、dlv、goplsなどの開発ツール事前インストール済み
- VS Code Go拡張機能自動セットアップ
- GitHub CLI統合
- Dockerサポート（Docker-in-Docker）

### ソースからビルド

```bash
git clone https://github.com/kaz-under-the-bridge/sysdig-vuls-utils.git
cd sysdig-vuls-utils
go build -o sysdig-vuls cmd/sysdig-vuls/main.go
```

### Goでインストール

```bash
go install github.com/kaz-under-the-bridge/sysdig-vuls-utils/cmd/sysdig-vuls@latest
```

## 設定

### APIトークン

このツールを使用するには有効なSysdig APIトークンが必要です。以下から取得できます：
- **Sysdig US2**: https://us2.app.sysdig.com/secure/settings/user
- **Sysdig EU**: https://eu1.app.sysdig.com/secure/settings/user

### 設定オプション

ツールは以下の複数の方法でAPIトークンとエンドポイントを設定できます：

1. **コマンドラインフラグ** （最優先）
2. **設定ファイル** （JSON形式）
3. **環境変数**
4. **デフォルト値** （最低優先度）

#### 環境変数

```bash
export SYSDIG_API_TOKEN="your_api_token_here"
export SYSDIG_API_URL="https://us2.app.sysdig.com"  # Optional, defaults to US2
```

#### 設定ファイル

JSON形式の設定ファイルを作成します（`examples/config.json`を参照）：

```json
{
  "api_token": "your_api_token_here",
  "api_url": "https://us2.app.sysdig.com"
}
```

## 使用方法

### コマンドラインインターフェース

```bash
sysdig-vuls [options]
```

#### オプション

- `-config string`: 設定ファイルへのパス
- `-token string`: Sysdig APIトークン（またはSYSDIG_API_TOKEN環境変数を使用）
- `-url string`: Sysdig APIベースURL（デフォルト: "https://us2.app.sysdig.com"）
- `-command string`: 実行するコマンド: list, get, update（デフォルト: "list"）
- `-id string`: 脆弱性ID（get/updateコマンドで必須）
- `-help`: ヘルプメッセージを表示
- `-version`: バージョン情報を表示

### 使用例

#### すべての脆弱性を一覧表示

```bash
# 環境変数を使用
export SYSDIG_API_TOKEN="your_token_here"
sysdig-vuls -command list

# コマンドラインフラグを使用
sysdig-vuls -token "your_token_here" -command list

# 設定ファイルを使用
sysdig-vuls -config config.json -command list
```

#### 特定の脆弱性を取得

```bash
sysdig-vuls -token "your_token_here" -command get -id CVE-2023-1234
```

#### 脆弱性ステータスの更新

```bash
sysdig-vuls -token "your_token_here" -command update -id CVE-2023-1234
```

## APIドキュメント

このツールはSysdig Secure APIをベースにしています。詳細なAPIドキュメントは以下を参照してください：

- **Sysdig APIドキュメント**: https://us2.app.sysdig.com/apidocs/secure?_product=SDS
- **Swagger UI**: https://us2.app.sysdig.com/secure/swagger.html

### サポートされているAPIエンドポイント

ツールは現在、以下のSysdig APIエンドポイントをサポートしています：

#### 脆弱性

- `GET /api/secure/v1/vulnerabilities` - すべての脆弱性を一覧表示
- `GET /api/secure/v1/vulnerabilities/{id}` - 特定の脆弱性を取得
- `PATCH /api/secure/v1/vulnerabilities/{id}` - 脆弱性を更新
- `GET /api/secure/v1/vulnerabilities?severity={level}` - 重要度でフィルタリング
- `GET /api/secure/v1/vulnerabilities?package={name}` - パッケージでフィルタリング

### APIレスポンス形式

```json
{
  "data": [
    {
      "id": "CVE-2023-1234",
      "cve": "CVE-2023-1234",
      "severity": "high",
      "status": "open",
      "description": "Vulnerability description",
      "packages": ["package1", "package2"],
      "score": 8.5,
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "publishedAt": "2023-01-01T00:00:00Z",
      "updatedAt": "2023-01-02T00:00:00Z",
      "metadata": {}
    }
  ],
  "page": 1,
  "totalPages": 10,
  "total": 250
}
```

## ライブラリとしての使用

独自のプロジェクトでGoライブラリとして使用することもできます：

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/kaz-under-the-bridge/sysdig-vuls-utils/pkg/sysdig"
)

func main() {
    client := sysdig.NewClient("https://us2.app.sysdig.com", "your_api_token")
    
    // List vulnerabilities
    vulns, err := client.ListVulnerabilities()
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Found %d vulnerabilities\n", len(vulns))
    
    // Get specific vulnerability
    vuln, err := client.GetVulnerability("CVE-2023-1234")
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Vulnerability: %s, Severity: %s\n", vuln.ID, vuln.Severity)
}
```

### 利用可能なクライアントメソッド

- `ListVulnerabilities() ([]Vulnerability, error)`
- `GetVulnerability(vulnID string) (*Vulnerability, error)`
- `UpdateVulnerability(vulnID string, updates map[string]interface{}) error`
- `ListVulnerabilitiesByPackage(packageName string) ([]Vulnerability, error)`
- `ListVulnerabilitiesBySeverity(severity string) ([]Vulnerability, error)`

## エラー処理

ツールは包括的なエラー処理を提供します：

- **認証エラー**: 無効または不足しているAPIトークン
- **ネットワークエラー**: 接続の問題やタイムアウト
- **APIエラー**: 無効なリクエストやサーバーエラー
- **Not Foundエラー**: 存在しない脆弱性をリクエストした場合

## リージョン別エンドポイント

Sysdigは複数のリージョンで運用されています。お使いのリージョンに適したエンドポイントを使用してください：

- **米国東部（デフォルト）**: `https://us2.app.sysdig.com`
- **米国西部**: `https://us3.app.sysdig.com`
- **EU**: `https://eu1.app.sysdig.com`
- **アジア太平洋**: `https://au1.app.sysdig.com`

## コントリビューション

1. リポジトリをフォーク
2. フィーチャーブランチを作成（`git checkout -b feature/amazing-feature`）
3. 変更をコミット（`git commit -m 'Add some amazing feature'`）
4. ブランチにプッシュ（`git push origin feature/amazing-feature`）
5. プルリクエストを作成

## ライセンス

このプロジェクトはMITライセンスのもとでライセンスされています - 詳細は[LICENSE](LICENSE)ファイルを参照してください。

## サポート

問題や質問がある場合：

1. [GitHub Issues](https://github.com/kaz-under-the-bridge/sysdig-vuls-utils/issues)を確認
2. [Sysdigドキュメント](https://docs.sysdig.com/)を参照
3. API固有の問題についてはSysdigサポートに連絡

## 変更履歴

### v1.0.0
- 初回リリース
- 基本的な脆弱性の一覧表示、取得、更新機能
- 設定ファイルと環境変数のサポート
- CLIツールとGoライブラリ
