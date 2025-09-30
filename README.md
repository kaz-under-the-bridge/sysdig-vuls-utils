# sysdig-vuls-utils

**Sysdig脆弱性管理APIツールセット**

SysdigのクラウドベースRCE（ランタイムコンテナセキュリティ）が検出した脆弱性を管理するためのGolang製コマンドラインツール＆ライブラリです。Sysdig V2 APIを使用して、パイプラインスキャン結果とランタイムスキャン結果から脆弱性データを取得・キャッシュし、SQLiteデータベースで管理します。

## 機能

### 主要機能
- **パイプライン・ランタイムスキャン結果の取得**: CI/CDパイプラインと本番環境の脆弱性データを並列取得
- **SQLiteキャッシュ**: スキャン結果をローカルSQLiteデータベースに保存
- **高度なフィルタリング**: 重要度、修正可能性、悪用可能性による絞り込み
- **Runtime制限機能**: asset.type別（workload/host/container）の取得件数制限
- **並行処理**: バッチサイズとAPIディレイによる効率的なデータ取得
- **レート制限対応**: 自動リトライ機構によるAPI制限回避

### データ管理
- **SQLiteデータベース**: 脆弱性データと詳細スキャン結果をリレーショナル管理
- **スキャン結果追跡**: パイプラインとランタイムのデータを統合管理
- **AWS情報**: AWSアカウント、リージョン、ワークロード情報の記録
- **コンテナ情報**: イメージ名、タグ、レジストリ情報の管理

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

## クイックスタート

### 推奨: スクリプトを使用した脆弱性データ取得

```bash
# デフォルト設定で実行（7日間、バッチサイズ2、API遅延3秒）
./scripts/fetch_vulnerabilities.sh

# パフォーマンスレベル指定（1-30）
./scripts/fetch_vulnerabilities.sh 7 perf 15  # バランス型

# 直接指定
./scripts/fetch_vulnerabilities.sh 3 2 3  # 3日間、バッチ2、遅延3秒
```

スクリプトは以下を自動実行します:
1. バイナリの自動ビルド（未ビルドの場合）
2. パイプラインスキャン結果の並列取得
3. ランタイムスキャン結果の並列取得
4. タイムスタンプ付きディレクトリにデータベース保存

### 生成されるファイル

```
data/YYYYMMDD_HHMMSS/
  ├── pipeline_vulnerabilities.db  # パイプラインスキャン結果
  └── runtime_vulnerabilities.db   # ランタイムスキャン結果
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

#### パイプラインスキャン結果の表示

```bash
# パイプラインスキャン結果を一覧表示（最新7日間）
./bin/sysdig-vuls -command pipeline -days 7

# パイプラインスキャン結果をキャッシュ
./bin/sysdig-vuls -command pipeline-cache -days 7 -cache ./data/pipeline.db
```

#### ランタイムスキャン結果の表示

```bash
# ランタイムスキャン結果を一覧表示（最新7日間、デフォルト制限適用）
./bin/sysdig-vuls -command runtime -days 7

# カスタム制限でランタイムスキャン結果をキャッシュ
./bin/sysdig-vuls -command runtime-cache -days 7 \
  -runtime-workload-limit 100 \
  -runtime-host-limit 20 \
  -runtime-container-limit 10 \
  -cache ./data/runtime.db
```

#### 特定スキャン結果の詳細表示

```bash
# スキャン結果IDを指定して詳細表示
./bin/sysdig-vuls -command scan-details -result-id YOUR_RESULT_ID

# High以上の脆弱性のみ表示
./bin/sysdig-vuls -command scan-details -result-id YOUR_RESULT_ID -above-high

# 受け入れていない脆弱性のみ表示
./bin/sysdig-vuls -command scan-details -result-id YOUR_RESULT_ID -only-not-accepted
```

#### リスク受容管理

```bash
# 受容済みリスク一覧
./bin/sysdig-vuls -command accepted-risks

# CVEをリスク受容として登録
./bin/sysdig-vuls -command create-acceptance \
  -create-acceptance "CVE-2023-1234,CVE-2023-5678" \
  -expiration-days 30
```

## SQLiteデータベース分析

生成されたSQLiteデータベースは標準的なSQLツールで分析できます。

### 基本的な分析クエリ

```sql
-- 重要度別の脆弱性集計
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
WHERE scan_type = 'runtime'
GROUP BY severity_value
ORDER BY severity_value DESC;

-- 最も脆弱性が多いイメージTop 10
SELECT
  pull_string,
  COUNT(*) as vuln_count,
  SUM(CASE WHEN severity_value >= 3 THEN 1 ELSE 0 END) as high_critical
FROM scan_results
WHERE scan_type = 'pipeline'
GROUP BY pull_string
ORDER BY high_critical DESC, vuln_count DESC
LIMIT 10;

-- asset.type別の脆弱性分布
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

## APIドキュメント

このツールはSysdig Secure V2 APIを使用しています。詳細なAPIドキュメントは以下を参照してください：

- **Sysdig APIドキュメント**: https://us2.app.sysdig.com/apidocs/secure?_product=SDS
- **Swagger UI**: https://us2.app.sysdig.com/secure/swagger.html

### 主要エンドポイント

- `GET /api/scanning/v1/resultsDirect/{resultID}/vulnPkgs` - スキャン結果の脆弱性詳細取得
- `GET /secure/vulnerability/v1/pipeline-results` - パイプラインスキャン結果一覧
- `GET /secure/vulnerability/v1/runtime-results` - ランタイムスキャン結果一覧
- `GET /secure/vulnerability/v1beta1/accepted-risks` - リスク受容一覧
- `POST /secure/vulnerability/v1beta1/accepted-risks` - リスク受容作成

## 開発

### ビルドとテスト

このプロジェクトはTaskfile.ymlでタスク管理しています：

```bash
# タスク一覧表示
task --list

# ビルド
task build

# テスト実行
task test

# コード品質チェック
task check
```

### リージョン別エンドポイント

お使いのリージョンに適したエンドポイントを`.devcontainer/.env`に設定してください：

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
- Sysdig V2 API対応
- パイプライン・ランタイムスキャン結果の並列取得
- SQLiteキャッシュ機能
- Runtime制限機能（asset.type別）
- バッチ処理とレート制限対応
- リスク受容管理機能
- 自動レポート生成スクリプト

### v1.0.0
- 初回リリース
- 基本的な脆弱性の一覧表示、取得機能
- 設定ファイルと環境変数のサポート
