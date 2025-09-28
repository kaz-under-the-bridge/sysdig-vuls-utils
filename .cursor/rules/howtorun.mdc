# Sysdig脆弱性分析 - SQLiteベース取得・分析ガイド

## 環境準備

### 1. 認証情報設定
```bash
# .devcontainer/.envファイルから環境変数を読み込み
export SYSDIG_API_TOKEN="your_token_here"
export SYSDIG_API_URL="https://us2.app.sysdig.com"
```

### 2. ツールビルド
```bash
make build
# または
go build -o bin/sysdig-vuls cmd/sysdig-vuls/main.go
```

## SQLiteベース脆弱性データ取得

### 基本的な脆弱性データ取得
```bash
# 全脆弱性をSQLiteに保存
./bin/sysdig-vuls -command cache -cache-type sqlite -cache ./data/vulnerabilities.db

# Critical/High重要度の修正・エクスプロイト可能な脆弱性のみ
./bin/sysdig-vuls -command cache -cache-type sqlite -cache ./data/critical_vulns.db -severity "critical,high" -fixable -exploitable

# 特定重要度のみ
./bin/sysdig-vuls -command cache -cache-type sqlite -cache ./data/high_vulns.db -severity high
```

### パイプライン・ランタイム結果取得
```bash
# パイプラインスキャン結果
./bin/sysdig-vuls -command pipeline -output table

# ランタイムスキャン結果
./bin/sysdig-vuls -command runtime -output table

# 特定スキャンの詳細（result-idが必要）
./bin/sysdig-vuls -command scan-details -result-id "your-result-id"
```

## SQLiteデータベース分析

### データベース接続
```bash
sqlite3 ./data/vulnerabilities.db
```

### 基本的な分析クエリ

#### 脆弱性統計サマリー
```sql
SELECT
    severity,
    COUNT(*) as total,
    SUM(CASE WHEN fixable = 1 THEN 1 ELSE 0 END) as fixable,
    SUM(CASE WHEN exploitable = 1 THEN 1 ELSE 0 END) as exploitable,
    SUM(CASE WHEN fixable = 1 AND exploitable = 1 THEN 1 ELSE 0 END) as fixable_exploitable
FROM vulnerabilities
GROUP BY severity
ORDER BY CASE severity
    WHEN 'critical' THEN 1
    WHEN 'high' THEN 2
    WHEN 'medium' THEN 3
    WHEN 'low' THEN 4 END;
```

#### AWSアカウント別リスク分析
```sql
SELECT
    ar.account_id,
    ar.resource_type,
    COUNT(DISTINCT v.id) as vuln_count,
    COUNT(CASE WHEN v.severity = 'critical' THEN 1 END) as critical_count,
    COUNT(CASE WHEN v.severity = 'high' THEN 1 END) as high_count,
    COUNT(CASE WHEN v.fixable = 1 AND v.exploitable = 1 THEN 1 END) as actionable_count
FROM vulnerabilities v
JOIN aws_resources ar ON v.id = ar.vulnerability_id
GROUP BY ar.account_id, ar.resource_type
ORDER BY critical_count DESC, high_count DESC;
```

#### 危険なパッケージランキング
```sql
SELECT
    vp.package_name,
    COUNT(*) as total_vulns,
    COUNT(CASE WHEN v.severity IN ('critical', 'high') THEN 1 END) as critical_high,
    COUNT(CASE WHEN v.fixable = 1 THEN 1 END) as fixable,
    AVG(v.score) as avg_score
FROM vulnerability_packages vp
JOIN vulnerabilities v ON vp.vulnerability_id = v.id
GROUP BY vp.package_name
HAVING total_vulns >= 3
ORDER BY critical_high DESC, avg_score DESC
LIMIT 20;
```

#### 検出場所別分析
```sql
SELECT
    ds.type as detection_type,
    ds.location,
    ds.cluster_name,
    COUNT(DISTINCT v.id) as unique_vulns,
    COUNT(CASE WHEN v.severity IN ('critical', 'high') THEN 1 END) as high_risk
FROM detection_sources ds
JOIN vulnerabilities v ON ds.vulnerability_id = v.id
GROUP BY ds.type, ds.location, ds.cluster_name
HAVING high_risk > 0
ORDER BY high_risk DESC, unique_vulns DESC;
```

#### コンテナイメージ別脆弱性
```sql
SELECT
    ci.registry,
    ci.image_name,
    ci.image_tag,
    COUNT(DISTINCT v.id) as vulns,
    COUNT(CASE WHEN v.severity = 'critical' THEN 1 END) as critical,
    COUNT(CASE WHEN v.severity = 'high' THEN 1 END) as high
FROM container_info ci
JOIN vulnerabilities v ON ci.vulnerability_id = v.id
GROUP BY ci.registry, ci.image_name, ci.image_tag
HAVING vulns > 0
ORDER BY critical DESC, high DESC, vulns DESC;
```

## データベーススキーマ確認

```sql
-- テーブル一覧
.tables

-- 各テーブルの構造確認
.schema vulnerabilities
.schema aws_resources
.schema vulnerability_packages
.schema detection_sources
.schema container_info
```

## 分析用インデックス作成

```sql
-- パフォーマンス向上のためのインデックス
CREATE INDEX IF NOT EXISTS idx_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_fixable ON vulnerabilities(fixable);
CREATE INDEX IF NOT EXISTS idx_exploitable ON vulnerabilities(exploitable);
CREATE INDEX IF NOT EXISTS idx_score ON vulnerabilities(score);
CREATE INDEX IF NOT EXISTS idx_aws_account ON aws_resources(account_id);
CREATE INDEX IF NOT EXISTS idx_aws_resource_type ON aws_resources(resource_type);
CREATE INDEX IF NOT EXISTS idx_package ON vulnerability_packages(package_name);
CREATE INDEX IF NOT EXISTS idx_detection_type ON detection_sources(type);
```

## CSV出力（Excelでの分析用）

```bash
# CSV形式で出力
./bin/sysdig-vuls -command cache -cache-type csv -cache ./data/vulnerabilities.csv -severity "critical,high" -fixable

# SQLiteからCSVエクスポート
sqlite3 -header -csv ./data/vulnerabilities.db "SELECT * FROM vulnerabilities WHERE severity IN ('critical', 'high');" > critical_vulns.csv
```

## 定期実行スクリプト例

```bash
#!/bin/bash
# update_vulns.sh

# データベース更新
./bin/sysdig-vuls -command cache -cache-type sqlite -cache ./data/vulnerabilities.db

# 統計レポート生成
sqlite3 ./data/vulnerabilities.db < analysis_queries.sql > daily_report.txt

# CSV出力
sqlite3 -header -csv ./data/vulnerabilities.db "SELECT * FROM vulnerabilities WHERE severity IN ('critical', 'high') AND fixable = 1;" > daily_critical_fixable.csv

echo "脆弱性データ更新完了: $(date)"
```

## トラブルシューティング

### よくあるエラー
```bash
# APIトークンエラー
echo $SYSDIG_API_TOKEN  # 設定確認

# SQLiteファイルロック
lsof ./data/vulnerabilities.db  # 使用中プロセス確認

# 権限エラー
chmod 755 bin/sysdig-vuls
mkdir -p data
```

### デバッグモード
```bash
# 詳細ログ出力
./bin/sysdig-vuls -command list -output detailed

# API接続テスト
curl -H "Authorization: Bearer $SYSDIG_API_TOKEN" https://api.us2.sysdig.com/secure/vulnerability/v1/pipeline-results
```

## 分析のポイント

1. **最優先対応**: Critical + Fixable + Exploitable
2. **AWS環境別リスク**: アカウント・リソースタイプごとの脆弱性分布
3. **パッケージ管理**: 最も脆弱性の多いパッケージ特定
4. **検出場所分析**: Runtime vs Container vs Image Repo
5. **時系列トレンド**: published_at, updated_atを活用した傾向分析