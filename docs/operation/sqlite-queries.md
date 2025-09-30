# SQLite クエリチートシート

## SQLite 実行コマンド

### データベースへの接続

```bash
# Pipeline scan results データベースに接続
sqlite3 data/pipeline_scan_results.db

# Runtime scan results データベースに接続
sqlite3 data/runtime_scan_results.db

# 読み取り専用モードで接続（安全）
sqlite3 -readonly data/pipeline_scan_results.db
```

### 便利な実行オプション

```bash
# ヘッダー付きで表示
sqlite3 -header data/pipeline_scan_results.db "SELECT * FROM scan_results LIMIT 5;"

# CSV形式で出力
sqlite3 -header -csv data/pipeline_scan_results.db "SELECT * FROM scan_results LIMIT 5;"

# タブ区切りで出力
sqlite3 -separator $'\t' data/pipeline_scan_results.db "SELECT * FROM scan_results LIMIT 5;"

# 結果をファイルに出力
sqlite3 -header -csv data/pipeline_scan_results.db "SELECT * FROM scan_vulnerabilities WHERE severity='critical';" > critical_vulns.csv

# SQLファイルの実行
sqlite3 data/pipeline_scan_results.db < analysis_queries.sql

# ワンライナークエリ実行（シェルスクリプト用）
sqlite3 data/pipeline_scan_results.db "SELECT COUNT(*) FROM scan_vulnerabilities WHERE severity IN ('critical', 'high') AND fixable = 1 AND exploitable = 1;"
```

### SQLite CLI 内での便利コマンド

```sql
-- データベース内で実行できる便利コマンド

-- テーブル一覧表示
.tables

-- スキーマ表示
.schema scan_results
.schema scan_vulnerabilities

-- インデックス一覧
.indices

-- データベース情報
.dbinfo

-- ヘッダー表示ON/OFF
.headers on
.headers off

-- 出力モード変更
.mode table      -- 表形式（デフォルト）
.mode csv        -- CSV形式
.mode tabs       -- タブ区切り
.mode column     -- カラム整列
.mode json       -- JSON形式

-- 出力先変更
.output result.csv    -- ファイルに出力
.output stdout        -- 標準出力に戻す

-- SQLファイル実行
.read queries.sql

-- 終了
.quit
.exit
```

### 実用的なワンライナー例

```bash
# 優先対応が必要な脆弱性の件数をすぐに確認
sqlite3 data/pipeline_scan_results.db "SELECT COUNT(*) as priority_count FROM scan_vulnerabilities WHERE severity IN ('critical', 'high') AND fixable = 1 AND exploitable = 1;"

# AWSアカウント別の危険度確認
sqlite3 -header -csv data/pipeline_scan_results.db "SELECT aws_account_name, SUM(critical_count) as critical, SUM(high_count) as high FROM scan_results GROUP BY aws_account_name ORDER BY critical DESC;" > account_risk.csv

# 最も危険なワークロードTop10
sqlite3 -header data/pipeline_scan_results.db "SELECT workload_name, critical_count, high_count FROM scan_results WHERE critical_count > 0 OR high_count > 0 ORDER BY critical_count DESC, high_count DESC LIMIT 10;"
```

## データベース概要

Sysdig脆弱性管理ツールでは、スキャン結果と脆弱性情報をSQLiteデータベースに保存しています。

## 主要テーブル構造

### scan_results テーブル
スキャン結果の基本情報
```sql
-- テーブル構造
result_id TEXT UNIQUE NOT NULL,        -- スキャン結果ID
scan_type TEXT NOT NULL,               -- "pipeline" or "runtime"
created_at TEXT,                       -- スキャン実行日時
pull_string TEXT,                      -- コンテナイメージの pull string
aws_account_id TEXT,                   -- AWSアカウントID
aws_account_name TEXT,                 -- AWSアカウント名
aws_region TEXT,                       -- AWSリージョン
workload_type TEXT,                    -- "ecs", "lambda", "host"
workload_name TEXT,                    -- ワークロード名
cluster_name TEXT,                     -- ECSクラスター名
container_name TEXT,                   -- コンテナ名
container_image TEXT,                  -- コンテナイメージ名
critical_count INTEGER,                -- Critical脆弱性数
high_count INTEGER,                    -- High脆弱性数
medium_count INTEGER,                  -- Medium脆弱性数
low_count INTEGER,                     -- Low脆弱性数
total_count INTEGER,                   -- 総脆弱性数
cached_at DATETIME                     -- キャッシュ日時
```

### scan_vulnerabilities テーブル
各スキャン結果の詳細脆弱性情報
```sql
-- テーブル構造
result_id TEXT NOT NULL,               -- スキャン結果ID (scan_resultsと紐づけ)
vuln_id TEXT NOT NULL,                 -- 脆弱性ID
vuln_name TEXT,                        -- CVE番号など
severity TEXT,                         -- 重要度 (critical/high/medium/low)
disclosure_date TEXT,                  -- 公開日
package_ref TEXT,                      -- パッケージ参照ID
package_name TEXT,                     -- パッケージ名
package_path TEXT,                     -- パッケージパス
fixable BOOLEAN,                       -- 修正可能フラグ
exploitable BOOLEAN,                   -- 悪用可能フラグ
fixed_version TEXT                     -- 修正バージョン
```

## 基本クエリ

### 1. データベース内容の確認

```sql
-- テーブル一覧
.tables

-- スキーマ確認
.schema scan_results
.schema scan_vulnerabilities

-- 各テーブルの件数確認
SELECT 'scan_results' as table_name, COUNT(*) as count FROM scan_results
UNION ALL
SELECT 'scan_vulnerabilities' as table_name, COUNT(*) as count FROM scan_vulnerabilities;
```

### 2. スキャン結果の概要

```sql
-- スキャンタイプ別の結果数
SELECT scan_type, COUNT(*) as scan_count
FROM scan_results
GROUP BY scan_type;

-- 最新のスキャン結果 (上位10件)
SELECT result_id, scan_type, created_at, aws_account_name, workload_name,
       critical_count, high_count, total_count
FROM scan_results
ORDER BY datetime(created_at) DESC
LIMIT 10;
```

### 3. 脆弱性統計

```sql
-- 重要度別脆弱性統計
SELECT severity, COUNT(*) as count
FROM scan_vulnerabilities
GROUP BY severity
ORDER BY CASE severity
    WHEN 'critical' THEN 1
    WHEN 'high' THEN 2
    WHEN 'medium' THEN 3
    WHEN 'low' THEN 4
END;

-- fixable かつ exploitable な脆弱性統計
SELECT severity,
       COUNT(*) as total,
       SUM(CASE WHEN fixable = 1 THEN 1 ELSE 0 END) as fixable,
       SUM(CASE WHEN exploitable = 1 THEN 1 ELSE 0 END) as exploitable,
       SUM(CASE WHEN fixable = 1 AND exploitable = 1 THEN 1 ELSE 0 END) as fixable_exploitable
FROM scan_vulnerabilities
WHERE severity IN ('critical', 'high')
GROUP BY severity;
```

## 高度なクエリ（分析用）

### 4. Critical & High 脆弱性の詳細分析

```sql
-- Critical/High で fixable かつ exploitable な脆弱性の詳細
SELECT DISTINCT
    sv.vuln_name,
    sv.severity,
    sv.package_name,
    sv.package_path,
    sv.fixed_version,
    sr.aws_account_name,
    sr.workload_type,
    sr.workload_name,
    sr.pull_string
FROM scan_vulnerabilities sv
JOIN scan_results sr ON sv.result_id = sr.result_id
WHERE sv.severity IN ('critical', 'high')
  AND sv.fixable = 1
  AND sv.exploitable = 1
ORDER BY
    CASE sv.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 END,
    sv.vuln_name;
```

### 5. AWSアカウント別リスク分析

```sql
-- AWSアカウント別の脆弱性分布
SELECT
    sr.aws_account_name,
    sr.aws_account_id,
    COUNT(DISTINCT sr.result_id) as scan_count,
    SUM(sr.critical_count) as total_critical,
    SUM(sr.high_count) as total_high,
    AVG(CAST(sr.critical_count + sr.high_count AS FLOAT)) as avg_high_risk
FROM scan_results sr
WHERE sr.aws_account_name IS NOT NULL
GROUP BY sr.aws_account_name, sr.aws_account_id
ORDER BY total_critical DESC, total_high DESC;
```

### 6. ワークロード別リスク分析

```sql
-- ワークロードタイプ別の脆弱性統計
SELECT
    sr.workload_type,
    COUNT(DISTINCT sr.result_id) as workload_count,
    SUM(sr.critical_count) as total_critical,
    SUM(sr.high_count) as total_high,
    ROUND(AVG(CAST(sr.critical_count + sr.high_count AS FLOAT)), 2) as avg_high_risk
FROM scan_results sr
WHERE sr.workload_type IS NOT NULL
GROUP BY sr.workload_type
ORDER BY total_critical DESC;

-- 最も危険なワークロード (Top 20)
SELECT
    sr.aws_account_name,
    sr.workload_type,
    sr.workload_name,
    sr.critical_count,
    sr.high_count,
    (sr.critical_count + sr.high_count) as high_risk_total,
    sr.pull_string
FROM scan_results sr
WHERE sr.critical_count > 0 OR sr.high_count > 0
ORDER BY (sr.critical_count + sr.high_count) DESC
LIMIT 20;
```

### 7. パッケージ別脆弱性分析

```sql
-- 最も脆弱性の多いパッケージ (Top 15)
SELECT
    sv.package_name,
    COUNT(*) as vuln_count,
    SUM(CASE WHEN sv.severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
    SUM(CASE WHEN sv.severity = 'high' THEN 1 ELSE 0 END) as high_count,
    SUM(CASE WHEN sv.fixable = 1 THEN 1 ELSE 0 END) as fixable_count,
    SUM(CASE WHEN sv.exploitable = 1 THEN 1 ELSE 0 END) as exploitable_count
FROM scan_vulnerabilities sv
WHERE sv.package_name IS NOT NULL AND sv.package_name != ''
GROUP BY sv.package_name
HAVING vuln_count >= 3
ORDER BY critical_count DESC, high_count DESC, vuln_count DESC
LIMIT 15;
```

### 8. 時系列分析

```sql
-- 日別スキャン実行統計
SELECT
    DATE(sr.created_at) as scan_date,
    sr.scan_type,
    COUNT(*) as scan_count,
    SUM(sr.critical_count) as daily_critical,
    SUM(sr.high_count) as daily_high
FROM scan_results sr
WHERE sr.created_at IS NOT NULL
GROUP BY DATE(sr.created_at), sr.scan_type
ORDER BY scan_date DESC, sr.scan_type;
```

### 9. 重複・未対応脆弱性の確認

```sql
-- 同じCVEが複数のワークロードで検出されている件数
SELECT
    sv.vuln_name,
    sv.severity,
    COUNT(DISTINCT sr.result_id) as affected_workloads,
    COUNT(DISTINCT sr.aws_account_name) as affected_accounts,
    GROUP_CONCAT(DISTINCT sr.workload_type) as workload_types
FROM scan_vulnerabilities sv
JOIN scan_results sr ON sv.result_id = sr.result_id
WHERE sv.severity IN ('critical', 'high')
  AND sv.fixable = 1
GROUP BY sv.vuln_name, sv.severity
HAVING affected_workloads >= 5
ORDER BY affected_workloads DESC;
```

## 実用的なフィルタクエリ

### 10. 優先対応すべき脆弱性

```sql
-- 【最優先】Critical + Fixable + Exploitable
SELECT DISTINCT
    sv.vuln_name as CVE,
    sv.package_name as Package,
    sv.fixed_version as FixVersion,
    sr.aws_account_name as Account,
    sr.workload_name as Workload,
    sr.pull_string as Image
FROM scan_vulnerabilities sv
JOIN scan_results sr ON sv.result_id = sr.result_id
WHERE sv.severity = 'critical'
  AND sv.fixable = 1
  AND sv.exploitable = 1
ORDER BY sv.vuln_name;

-- 【次優先】High + Fixable + Exploitable
SELECT DISTINCT
    sv.vuln_name as CVE,
    sv.package_name as Package,
    sv.fixed_version as FixVersion,
    sr.aws_account_name as Account,
    sr.workload_name as Workload,
    sr.pull_string as Image
FROM scan_vulnerabilities sv
JOIN scan_results sr ON sv.result_id = sr.result_id
WHERE sv.severity = 'high'
  AND sv.fixable = 1
  AND sv.exploitable = 1
ORDER BY sv.vuln_name;
```

## データエクスポート

### 11. CSV形式での出力

```sql
-- ヘッダー付きCSV出力（SQLite CLI使用）
.headers on
.mode csv
.output priority_vulnerabilities.csv

SELECT DISTINCT
    sv.vuln_name as CVE,
    sv.severity as Severity,
    sv.package_name as PackageName,
    sv.fixed_version as FixedVersion,
    CASE WHEN sv.fixable = 1 THEN 'Yes' ELSE 'No' END as Fixable,
    CASE WHEN sv.exploitable = 1 THEN 'Yes' ELSE 'No' END as Exploitable,
    sr.aws_account_name as AWSAccount,
    sr.workload_type as WorkloadType,
    sr.workload_name as WorkloadName,
    sr.pull_string as ContainerImage
FROM scan_vulnerabilities sv
JOIN scan_results sr ON sv.result_id = sr.result_id
WHERE sv.severity IN ('critical', 'high')
  AND sv.fixable = 1
  AND sv.exploitable = 1
ORDER BY
    CASE sv.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 END,
    sv.vuln_name;

.output stdout
```

## データベースメンテナンス

### 12. パフォーマンス向上

```sql
-- インデックス確認
.indices

-- 統計情報更新（クエリ最適化）
ANALYZE;

-- データベースサイズ確認
.dbinfo

-- テーブルサイズ確認
SELECT
    'scan_results' as table_name,
    COUNT(*) as row_count,
    pg_size_pretty(pg_total_relation_size('scan_results')) as size
FROM scan_results
UNION ALL
SELECT
    'scan_vulnerabilities' as table_name,
    COUNT(*) as row_count,
    'N/A' as size  -- SQLiteの場合
FROM scan_vulnerabilities;
```

## 使用例

```bash
# SQLiteデータベースに接続
sqlite3 data/pipeline_scan_results.db

# 優先対応脆弱性をすぐに確認
sqlite3 data/pipeline_scan_results.db "
SELECT COUNT(*) as critical_fixable_exploitable
FROM scan_vulnerabilities
WHERE severity = 'critical' AND fixable = 1 AND exploitable = 1;"

# CSVで出力
sqlite3 -header -csv data/pipeline_scan_results.db "
SELECT DISTINCT vuln_name, severity, package_name, fixed_version,
       aws_account_name, workload_name
FROM scan_vulnerabilities sv
JOIN scan_results sr ON sv.result_id = sr.result_id
WHERE sv.severity IN ('critical', 'high') AND sv.fixable = 1 AND sv.exploitable = 1
ORDER BY severity, vuln_name;" > priority_vulns.csv
```

## Tips

1. **パフォーマンス**: 大量データの場合は `LIMIT` を使用
2. **重複除去**: `DISTINCT` を活用して重複結果を避ける
3. **時間範囲指定**: `WHERE datetime(created_at) >= datetime('now', '-7 days')` で期間限定
4. **正規化**: CVE番号は `vuln_name` フィールドに格納
5. **NULL対応**: `IS NOT NULL` や `COALESCE()` を活用

このチートシートを参考に、効率的な脆弱性分析を実施してください。