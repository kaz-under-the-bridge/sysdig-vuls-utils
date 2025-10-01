# テスト実装戦略

## 概要

このドキュメントは、sysdig-vuls-utilsプロジェクトにおけるテスト実装の戦略と方針を定義します。API仕様書（`docs/sysdig-api-ref`）に準拠した堅牢なテストスイートを構築し、品質を保証します。

## 現状分析

### 既存のテスト資産

- **client_test.go.bak**: 古いAPI構造に基づくテスト（削除済み）
- **非推奨メソッド**: V2 vulnPkgs API関連のコード（削除完了）

### テスト対象コード

| パッケージ | ファイル | 優先度 | 説明 |
|----------|---------|-------|------|
| `pkg/sysdig` | `client.go` | 🔴 最高 | APIクライアント（最重要） |
| `pkg/cache` | `cache.go` | 🟡 高 | SQLiteキャッシュ |
| `pkg/config` | `config.go` | 🟢 中 | 設定管理 |
| `pkg/output` | `table.go` | 🟢 中 | 出力フォーマット |
| `cmd/sysdig-vuls` | `main.go` | 🟢 中 | CLIロジック |

**注意**: 優先度「高」以上のみを実装対象とします。優先度「中」以下は本戦略の対象外です。

---

## テスト戦略（2層アプローチ）

このプロジェクトはCLIツールであり、実際のSysdig APIと通信するため、E2Eテストは不要と判断しました。モックサーバーを使った統合テストで十分な品質を確保できます。

### Layer 1: ユニットテスト（_test.go）

各パッケージに`_test.go`を配置し、ロジックを単体でテスト。

#### 実装対象（優先度：高以上）

| パッケージ | テストファイル | 優先度 | テスト内容 |
|----------|--------------|-------|----------|
| `pkg/sysdig` | `client_test.go` | 🔴 最高 | API呼び出し、データ変換、エラーハンドリング |
| `pkg/cache` | `cache_test.go` | 🟡 高 | SQLite操作、CRUD、トランザクション |

#### 実装方針

```go
// pkg/sysdig/client_test.go の構造
package sysdig_test

import (
    "testing"
    "github.com/kaz-under-the-bridge/sysdig-vuls-utils/pkg/sysdig"
    "github.com/kaz-under-the-bridge/sysdig-vuls-utils/internal/testutil"
)

// 1. 基本的な構造体テスト
func TestNewClient(t *testing.T) {
    client := sysdig.NewClient("https://test.example.com", "test-token")
    if client == nil {
        t.Fatal("Expected client to be created")
    }
}

// 2. HTTPモックを使ったAPIテスト
func TestGetFullScanResult(t *testing.T) {
    server := testutil.NewMockSysdigServer()
    defer server.Close()

    client := sysdig.NewClient(server.URL, "test-token")
    result, err := client.GetFullScanResult("scan-1234")

    if err != nil {
        t.Fatalf("Unexpected error: %v", err)
    }
    if result.Metadata.PullString != "nginx:latest" {
        t.Errorf("Expected nginx:latest, got %s", result.Metadata.PullString)
    }
}

// 3. テーブル駆動テスト
func TestSeverityStringToInt(t *testing.T) {
    tests := []struct {
        name     string
        severity string
        expected int
    }{
        {"critical", "critical", 4},
        {"high", "high", 3},
        {"medium", "medium", 2},
        {"low", "low", 1},
        {"negligible", "negligible", 5},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := sysdig.SeverityStringToInt(tt.severity)
            if result != tt.expected {
                t.Errorf("Expected %d, got %d", tt.expected, result)
            }
        })
    }
}
```

#### テストカバレッジ目標

- **pkg/sysdig**: 80%以上
- **pkg/cache**: 70%以上

---

### Layer 2: 統合テスト（internal/testutil）

共通のモックサーバー・テストユーティリティを`internal/testutil`に集約。

#### ディレクトリ構造

```
internal/testutil/
├── mock_server.go          # モックSysdig APIサーバー
├── fixtures.go             # テストデータ（API ref準拠）
├── assertions.go           # カスタムアサーション
└── testutil_test.go        # テストユーティリティ自体のテスト
```

#### モックサーバーの設計

```go
// internal/testutil/mock_server.go
package testutil

import (
    "net/http"
    "net/http/httptest"
)

type MockSysdigServer struct {
    *httptest.Server
    Responses map[string]MockResponse
}

type MockResponse struct {
    StatusCode int
    Body       interface{}
    Headers    map[string]string
}

// NewMockSysdigServer creates a mock Sysdig API server
// API ref仕様に準拠したレスポンスを返す
func NewMockSysdigServer() *MockSysdigServer {
    mux := http.NewServeMux()

    // docs/sysdig-api-refの各エンドポイントを実装
    mux.HandleFunc("/secure/vulnerability/v1/pipeline-results", handlePipelineResults)
    mux.HandleFunc("/secure/vulnerability/v1/runtime-results", handleRuntimeResults)
    mux.HandleFunc("/secure/vulnerability/v1/results/", handleFullScanResult)
    mux.HandleFunc("/secure/vulnerability/v1beta1/accepted-risks", handleAcceptedRisks)

    server := httptest.NewServer(mux)
    return &MockSysdigServer{
        Server:    server,
        Responses: make(map[string]MockResponse),
    }
}

func handlePipelineResults(w http.ResponseWriter, r *http.Request) {
    // docs/sysdig-api-ref/get-listof-pipeline-scan-results.md の
    // response exampleを返す
    response := PipelineResultsFixture()
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

// 他のエンドポイントも同様に実装
```

#### fixtures.goの設計

```go
// internal/testutil/fixtures.go
package testutil

import "github.com/kaz-under-the-bridge/sysdig-vuls-utils/pkg/sysdig"

// PipelineResultsFixture returns test data for pipeline results
// Based on: docs/sysdig-api-ref/get-listof-pipeline-scan-results.md
func PipelineResultsFixture() *sysdig.ScanResultsResponse {
    return &sysdig.ScanResultsResponse{
        Data: []sysdig.ScanResult{
            {
                ResultID:               "scan-1234",
                CreatedAt:              "2024-01-22T08:51:46.016464Z",
                ImageID:                "sha256:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
                PullString:             "nginx:latest",
                PolicyEvaluationResult: "passed",
                VulnTotalBySeverity: sysdig.VulnSeverityCount{
                    Critical:   12345,
                    High:       12345,
                    Medium:     12345,
                    Low:        12345,
                    Negligible: 12345,
                },
            },
        },
        Page: sysdig.ScanResultsPageInfo{
            Next:  "MTI0MjM0Cg==",
            Total: 1,
        },
    }
}

// FullScanResultFixture returns test data for full scan result
// Based on: docs/sysdig-api-ref/get-full-scan-result.md
func FullScanResultFixture() *sysdig.FullScanResult {
    return &sysdig.FullScanResult{
        AssetType: "containerImage",
        Stage:     "pipeline",
        Metadata: sysdig.ScanResultMetadata{
            Architecture: "arm64",
            Author:       "sysdig",
            BaseOS:       "debian",
            CreatedAt:    "2024-01-22T08:51:46.016464Z",
            Digest:       "sha256:77af4d6b9913e693e8d0b4b294fa62ade6054e6b2f1ffb617ac955dd63fb0182",
            ImageID:      "sha256:77af4d6b9913e693e8d0b4b294fa62ade6054e6b2f1ffb617ac955dd63fb0182",
            OS:           "debian",
            PullString:   "nginx:latest",
            Size:         10240,
        },
        Packages: map[string]sysdig.Package{
            "2772f8a6c73fa17": {
                Name:                "openssl",
                Version:             "1.2.3",
                Type:                "os",
                Path:                "/usr/local/bin/openssl",
                License:             "MIT",
                IsRunning:           true,
                IsRemoved:           false,
                SuggestedFix:        "1.2.3",
                VulnerabilitiesRefs: []string{"71af37c6a8f2772"},
            },
        },
        Vulnerabilities: map[string]sysdig.VulnerabilityInfo{
            "71af37c6a8f2772": {
                Name:           "CVE-2021-1234",
                Severity:       "high",
                DisclosureDate: "2021-01-02",
                FixVersion:     "1.2.3",
                Exploitable:    true,
                PackageRef:     "2772f8a6c73fa17",
                MainProvider:   "vulndb",
            },
        },
    }
}

// RuntimeResultsFixture returns test data for runtime results
// Based on: docs/sysdig-api-ref/get-listof-runtime-scan-results.md
func RuntimeResultsFixture() *sysdig.ScanResultsResponse {
    return &sysdig.ScanResultsResponse{
        Data: []sysdig.ScanResult{
            {
                ResultID:            "scan-1234",
                MainAssetName:       "nginx:latest",
                ResourceID:          "sha256:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
                IsRiskSpotlightEnabled: true,
                PolicyEvaluationResult: "passed",
                SbomID:              "sbom-1234",
                Scope: map[string]interface{}{
                    "asset.type":                "workload",
                    "kubernetes.cluster.name":   "prod-cluster-00",
                    "kubernetes.namespace.name": "foo",
                    "kubernetes.workload.name":  "bar",
                    "kubernetes.workload.type":  "deployment",
                },
                VulnTotalBySeverity: sysdig.VulnSeverityCount{
                    Critical:   12345,
                    High:       12345,
                    Medium:     12345,
                    Low:        12345,
                    Negligible: 12345,
                },
                RunningVulnTotalBySeverity: &sysdig.VulnSeverityCount{
                    Critical:   12345,
                    High:       12345,
                    Medium:     12345,
                    Low:        12345,
                    Negligible: 12345,
                },
            },
        },
        Page: sysdig.ScanResultsPageInfo{
            Next:  "MTI0MjM0Cg==",
            Total: 1,
        },
    }
}
```

---

## 実装フェーズ

### Phase 1: 基盤構築（優先度：高）

1. `internal/testutil/` ディレクトリの作成
2. `fixtures.go` にAPI ref準拠のテストデータを実装
   - PipelineResultsFixture
   - RuntimeResultsFixture
   - FullScanResultFixture
3. `mock_server.go` に基本的なモックサーバーを実装
   - /secure/vulnerability/v1/pipeline-results
   - /secure/vulnerability/v1/runtime-results
   - /secure/vulnerability/v1/results/{resultId}

### Phase 2: コアテスト（優先度：最高）

4. `pkg/sysdig/client_test.go` の実装
   - **NewClient**: クライアント生成
   - **GetFullScanResult**: 完全なスキャン結果取得
   - **GetScanResultVulnerabilities**: 脆弱性リストの構築
   - **ListPipelineResults**: パイプライン結果一覧（filterパラメータ含む）
   - **ListPipelineResultsWithFilter**: freeTextフィルタ
   - **ListRuntimeResults**: ランタイム結果一覧
   - **ListRuntimeResultsWithLimits**: asset.type別制限
   - **ListAcceptedRisks**: リスク受容一覧
   - **CreateAcceptedRisk**: リスク受容作成
   - **severityStringToInt**: 重要度変換

### Phase 3: キャッシュテスト（優先度：高）

5. `pkg/cache/cache_test.go` の実装
   - SQLite CRUD操作
   - scan_results テーブルの操作
   - scan_vulnerabilities テーブルの操作
   - リレーショナル整合性の検証
   - トランザクション処理

---

## テストの質を高めるポイント

### 1. API ref仕様との同期

```go
// ✅ Good: API refのresponse exampleをそのまま使用
func TestListPipelineResults_ResponseStructure(t *testing.T) {
    // docs/sysdig-api-ref/get-listof-pipeline-scan-results.md
    // のresponse exampleと一致することを確認
    server := testutil.NewMockSysdigServer()
    defer server.Close()

    client := sysdig.NewClient(server.URL, "test-token")
    results, err := client.ListPipelineResults()

    // API仕様の必須フィールドを確認
    assert.NoError(t, err)
    assert.NotEmpty(t, results[0].ResultID)
    assert.NotEmpty(t, results[0].ImageID)
    assert.NotEmpty(t, results[0].PullString)
}
```

### 2. テーブル駆動テスト

```go
// ✅ Good: 複数のケースを網羅
func TestFetchPipelineResults_Filters(t *testing.T) {
    tests := []struct {
        name           string
        filter         string
        expectedQuery  string
        expectedCount  int
    }{
        {
            name:          "no filter",
            filter:        "",
            expectedQuery: "",
            expectedCount: 10,
        },
        {
            name:          "nginx filter",
            filter:        "nginx",
            expectedQuery: "filter=freeText%20in%20%28%22nginx%22%29",
            expectedCount: 3,
        },
        {
            name:          "ir-worker filter",
            filter:        "ir-worker",
            expectedQuery: "filter=freeText%20in%20%28%22ir-worker%22%29",
            expectedCount: 5,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            server := testutil.NewMockSysdigServerWithFilter(tt.filter, tt.expectedCount)
            defer server.Close()

            client := sysdig.NewClient(server.URL, "test-token")
            results, err := client.ListPipelineResultsWithFilter(7, tt.filter)

            assert.NoError(t, err)
            assert.Len(t, results, tt.expectedCount)
        })
    }
}
```

### 3. モック vs 実サーバー切り替え

```go
// 環境変数で実サーバーテストも可能に
func getTestClient(t *testing.T) *sysdig.Client {
    if token := os.Getenv("SYSDIG_TEST_TOKEN"); token != "" {
        t.Log("Using real Sysdig API for testing")
        return sysdig.NewClient("https://us2.app.sysdig.com", token)
    }

    t.Log("Using mock server for testing")
    mockServer := testutil.NewMockSysdigServer()
    t.Cleanup(mockServer.Close)
    return sysdig.NewClient(mockServer.URL, "test-token")
}
```

### 4. エラーケースのテスト

```go
func TestGetFullScanResult_NotFound(t *testing.T) {
    server := testutil.NewMockSysdigServerWithError(404, "Not Found")
    defer server.Close()

    client := sysdig.NewClient(server.URL, "test-token")
    _, err := client.GetFullScanResult("non-existent-id")

    assert.Error(t, err)
    assert.Contains(t, err.Error(), "scan result not found")
}

func TestListPipelineResults_RateLimit(t *testing.T) {
    server := testutil.NewMockSysdigServerWithError(429, "Rate Limit Exceeded")
    defer server.Close()

    client := sysdig.NewClient(server.URL, "test-token")
    _, err := client.ListPipelineResults()

    assert.Error(t, err)
    assert.Contains(t, err.Error(), "429")
}
```

---

## 追加ツール・ライブラリの推奨

### testify/assert

アサーションを簡潔に記述。

```go
import "github.com/stretchr/testify/assert"

assert.Equal(t, expected, actual)
assert.NoError(t, err)
assert.Len(t, results, 10)
```

### go-cmp

構造体の詳細比較。

```go
import "github.com/google/go-cmp/cmp"

if diff := cmp.Diff(expected, actual); diff != "" {
    t.Errorf("Result mismatch (-want +got):\n%s", diff)
}
```

---

## 実装時の注意点

### 1. API仕様の変更追従

- `docs/sysdig-api-ref`を更新したらテストも更新
- CI/CDでAPI仕様とテストの整合性チェック
- fixtures.goのレスポンスはAPI refのresponse exampleと一致させる

### 2. 非推奨APIのテスト

- 非推奨メソッド（`GetVulnPackagesV2`, `GetAllVulnPackagesV2`）は削除済み
- テストは新しい公式API（`GetFullScanResult`, `GetScanResultVulnerabilities`）に集中

### 3. 並行処理のテスト

- `pipeline-cache`, `runtime-cache`の並行API呼び出しのテスト
- race detectorの活用: `go test -race ./...`

### 4. SQLiteのテスト

- インメモリDB（`:memory:`）を使用して高速化
- テスト後のクリーンアップを忘れずに
- トランザクションの整合性を確認

```go
func TestCache_CreateScanResult(t *testing.T) {
    // インメモリDBを使用
    cache, err := cache.NewCache(":memory:", "sqlite")
    if err != nil {
        t.Fatalf("Failed to create cache: %v", err)
    }
    defer cache.Close()

    // テストデータを挿入
    err = cache.CreateScanResult(/* ... */)
    assert.NoError(t, err)

    // 取得してデータを検証
    result, err := cache.GetScanResult(resultID)
    assert.NoError(t, err)
    assert.Equal(t, expectedPullString, result.PullString)
}
```

---

## テスト実行コマンド

```bash
# 静的解析（高速チェック）
task vet

# 全テスト実行（go vetを自動実行）
task test

# カバレッジ付きテスト
task test-coverage

# race detector付きテスト
task test-race

# 特定パッケージのみ
task test-pkg PKG=pkg/sysdig

# 実サーバーテスト（環境変数設定）
SYSDIG_TEST_TOKEN=xxx task test
```

**テストフロー:**
1. `task vet`: 静的解析で早期エラー検出（高速）
2. `task test`: ユニットテスト実行（go vetが前提条件として自動実行）
3. `task test-coverage`: カバレッジ測定

---

## 成功基準

### 必須

- ✅ `pkg/sysdig/client_test.go` の実装完了
- ✅ `pkg/cache/cache_test.go` の実装完了
- ✅ `internal/testutil` の基盤構築完了
- ✅ カバレッジ目標達成（sysdig: 80%、cache: 70%）
- ✅ 全テストがパス（`task test`）

### 推奨

- ✅ API ref仕様との整合性確認
- ✅ エラーケースの網羅的なテスト
- ✅ CI/CDパイプラインへの統合

---

## 今後の拡張（優先度：中以下、本戦略対象外）

- `pkg/config/config_test.go` の実装
- `pkg/output/table_test.go` の実装
- パフォーマンステスト
- 統合テストの自動化

**E2Eテストについて:**
このプロジェクトはCLIツールであり、実際のSysdig APIと通信するため、E2Eテストは実装しません。実環境でのテストは以下で代替します：
- 手動実行: `./bin/sysdig-vuls -command pipeline -days 7`
- スクリプト: `./scripts/fetch_vulnerabilities.sh`
- モックサーバーでの統合テスト: `internal/testutil`

---

## 関連ドキュメント

- [API仕様書: Pipeline Results](../sysdig-api-ref/get-listof-pipeline-scan-results.md)
- [API仕様書: Runtime Results](../sysdig-api-ref/get-listof-runtime-scan-results.md)
- [API仕様書: Full Scan Result](../sysdig-api-ref/get-full-scan-result.md)
- [プロジェクト概要](../CLAUDE.md)
