# sysdig-vuls-utils

**Sysdig脆弱性管理APIツールセット**

SysdigのクラウドベースRCE（ランタイムコンテナセキュリティ）が検出した脆弱性を管理するためのGolang製コマンドラインツール＆ライブラリです。Sysdig Cloud環境における脆弱性の一覧取得、詳細情報の取得、ステータス更新などが可能です。

## 機能

### 基本機能
- **脆弱性一覧の取得**: Sysdig環境内のすべての脆弱性を取得
- **脆弱性詳細の取得**: 特定の脆弱性の詳細情報を取得
- **脆弱性の更新**: 脆弱性のステータスやメタデータを変更

### 高度なフィルタリング
- **重要度でフィルタリング**: 重要度レベル（critical、high、medium、low）で脆弱性を検索
- **修正可能な脆弱性**: fixable=trueの脆弱性のみを表示
- **エクスプロイト可能**: exploitable=trueの脆弱性のみを表示
- **パッケージでフィルタリング**: 特定のパッケージに影響する脆弱性を検索
- **複合フィルタ**: 複数の条件を組み合わせた高度な検索

### データ管理
- **ローカルキャッシュ**: SQLiteまたはCSVによるローカルデータ保存
- **AWSリソース追跡**: EC2、Lambda、ECS、EKS、ECRの脆弱性を追跡
- **検出場所の判定**: runtime、container、image repoでの検出を記録
- **コンテナ情報**: イメージ名、タグ、レジストリ情報を管理

### 出力形式
- **テーブル形式**: 見やすいテーブル形式での出力
- **詳細ビュー**: 脆弱性の完全な情報表示
- **サマリービュー**: 統計情報と概要の表示
- **AWSリソースビュー**: AWS特化の脆弱性レポート
- **CSV/SQLite出力**: 分析ツール連携用のデータ出力

## インストール

### 前提条件

- Go 1.23以降
- 有効なSysdig APIトークン
- SQLite3（キャッシュ機能を使用する場合）

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

##### 基本オプション
- `-config string`: 設定ファイルへのパス
- `-token string`: Sysdig APIトークン（またはSYSDIG_API_TOKEN環境変数を使用）
- `-url string`: Sysdig APIベースURL（デフォルト: "https://us2.app.sysdig.com"）
- `-command string`: 実行するコマンド: list, filter, get, update, summary, cache（デフォルト: "list"）
- `-id string`: 脆弱性ID（get/updateコマンドで必須）
- `-help`: ヘルプメッセージを表示
- `-version`: バージョン情報を表示

##### フィルタオプション
- `-severity string`: 重要度でフィルタ（critical,high,medium,low）
- `-fixable`: 修正可能な脆弱性のみ表示
- `-exploitable`: エクスプロイト可能な脆弱性のみ表示

##### 出力オプション
- `-output string`: 出力形式: table, detailed, summary, aws（デフォルト: "table"）

##### キャッシュオプション
- `-cache string`: キャッシュファイルへのパス（デフォルト: "./cache/vulnerabilities.db"）
- `-cache-type string`: キャッシュタイプ: sqlite, csv（デフォルト: "sqlite"）

### 使用例

#### すべての脆弱性を一覧表示

```bash
# 環境変数を使用
export SYSDIG_API_TOKEN="your_token_here"
sysdig-vuls -command list

# テーブル形式で出力
sysdig-vuls -token "your_token_here" -command list -output table

# 詳細形式で出力
sysdig-vuls -token "your_token_here" -command list -output detailed
```

#### フィルタを使用した検索

```bash
# Criticalかつ修正可能な脆弱性のみ表示
sysdig-vuls -token "your_token_here" -command filter -severity critical -fixable

# HighとCriticalでエクスプロイト可能な脆弱性
sysdig-vuls -token "your_token_here" -command filter -severity "critical,high" -exploitable

# 修正可能かつエクスプロイト可能な脆弱性（自動的にcritical/highフィルタ）
sysdig-vuls -token "your_token_here" -command filter -fixable -exploitable
```

#### 脆弱性サマリーの表示

```bash
# 脆弱性の統計情報を表示
sysdig-vuls -token "your_token_here" -command summary
```

#### ローカルキャッシュへの保存

```bash
# SQLiteデータベースに保存
sysdig-vuls -token "your_token_here" -command cache -cache-type sqlite -cache ./data/vulns.db

# CSVファイルに保存（フィルタ付き）
sysdig-vuls -token "your_token_here" -command cache -cache-type csv -cache ./data/vulns.csv -severity "critical,high" -fixable
```

#### AWSリソース別の脆弱性表示

```bash
# AWSリソース形式で脆弱性を表示
sysdig-vuls -token "your_token_here" -command list -output aws
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

#### 基本メソッド
- `ListVulnerabilities() ([]Vulnerability, error)` - すべての脆弱性を取得
- `GetVulnerability(vulnID string) (*Vulnerability, error)` - 特定の脆弱性を取得
- `UpdateVulnerability(vulnID string, updates map[string]interface{}) error` - 脆弱性を更新

#### フィルタメソッド
- `ListVulnerabilitiesByPackage(packageName string) ([]Vulnerability, error)` - パッケージでフィルタ
- `ListVulnerabilitiesBySeverity(severity string) ([]Vulnerability, error)` - 重要度でフィルタ
- `ListVulnerabilitiesWithFilters(filter VulnerabilityFilter) ([]Vulnerability, error)` - 複合フィルタ
- `ListCriticalAndHighVulnerabilities() ([]Vulnerability, error)` - Critical/High、修正可能、エクスプロイト可能な脆弱性

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

### v2.0.0
- 高度なフィルタリング機能追加（fixable、exploitable）
- ローカルキャッシュ機能（SQLite/CSV）
- AWSリソース追跡機能
- 検出場所の判定機能（runtime、container、image repo）
- 複数の出力形式（table、detailed、summary、aws）
- コンテナ情報管理

### v1.0.0
- 初回リリース
- 基本的な脆弱性の一覧表示、取得、更新機能
- 設定ファイルと環境変数のサポート
- CLIツールとGoライブラリ
