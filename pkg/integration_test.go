// Package integration_test provides integration tests that walk through the full flow
package integration_test

import (
	"path/filepath"
	"testing"

	"github.com/kaz-under-the-bridge/sysdig-vuls-utils/internal/testutil"
	"github.com/kaz-under-the-bridge/sysdig-vuls-utils/pkg/cache"
	"github.com/kaz-under-the-bridge/sysdig-vuls-utils/pkg/sysdig"
)

// TestPipelineToSQLiteWalkthrough は、モックサーバーからパイプラインデータを取得してSQLiteに保存するまでの全フローをテスト
func TestPipelineToSQLiteWalkthrough(t *testing.T) {
	// Step 1: モックサーバーのセットアップ
	t.Log("Step 1: Setting up mock server")
	mockConfig := testutil.DefaultMockServerConfig()
	mockConfig.PipelinePageCount = 2 // 2ページ分のデータを返す
	server := testutil.NewMockServer(mockConfig)
	defer server.Close()
	t.Logf("Mock server started at: %s", server.URL)

	// Step 2: Sysdig APIクライアントの作成
	t.Log("Step 2: Creating Sysdig API client")
	client := sysdig.NewClient(server.URL, "test-token")
	if client == nil {
		t.Fatal("Failed to create Sysdig client")
	}

	// Step 3: パイプラインスキャン結果の取得
	t.Log("Step 3: Fetching pipeline scan results")
	pipelineResults, err := client.ListPipelineResultsWithDays(7)
	if err != nil {
		t.Fatalf("Failed to fetch pipeline results: %v", err)
	}
	t.Logf("Fetched %d pipeline scan results", len(pipelineResults))

	if len(pipelineResults) == 0 {
		t.Fatal("Expected at least 1 pipeline result, got 0")
	}

	// Step 4: 各スキャン結果の詳細な脆弱性情報を取得
	t.Log("Step 4: Fetching detailed vulnerability information for each scan result")
	vulnerabilities := make(map[string][]sysdig.Vulnerability)

	for _, result := range pipelineResults {
		t.Logf("  - Fetching vulnerabilities for result: %s (image: %s)", result.ResultID, result.PullString)
		vulns, err := client.GetScanResultVulnerabilities(result.ResultID)
		if err != nil {
			t.Logf("    Warning: Failed to fetch vulnerabilities for %s: %v", result.ResultID, err)
			vulnerabilities[result.ResultID] = []sysdig.Vulnerability{}
			continue
		}
		vulnerabilities[result.ResultID] = vulns
		t.Logf("    Found %d vulnerabilities", len(vulns))
	}

	// Step 5: SQLiteキャッシュの作成
	t.Log("Step 5: Creating SQLite cache")
	tempFile := filepath.Join(t.TempDir(), "pipeline_walkthrough.db")
	sqliteCache, err := cache.NewSQLiteCache(tempFile)
	if err != nil {
		t.Fatalf("Failed to create SQLite cache: %v", err)
	}
	defer sqliteCache.Close()
	t.Logf("SQLite cache created at: %s", tempFile)

	// Step 6: スキャン結果と脆弱性をSQLiteに保存
	t.Log("Step 6: Saving scan results and vulnerabilities to SQLite")
	err = sqliteCache.SaveScanResults("pipeline", pipelineResults, vulnerabilities)
	if err != nil {
		t.Fatalf("Failed to save scan results: %v", err)
	}
	t.Logf("Successfully saved %d scan results with their vulnerabilities", len(pipelineResults))

	// Step 7: 保存したデータを検証（ロードして確認）
	t.Log("Step 7: Verifying saved data by loading from SQLite")
	loadedResults, err := sqliteCache.LoadScanResults("pipeline", 30)
	if err != nil {
		t.Fatalf("Failed to load scan results: %v", err)
	}
	t.Logf("Loaded %d scan results from SQLite", len(loadedResults))

	if len(loadedResults) != len(pipelineResults) {
		t.Errorf("Loaded results count mismatch: got %d, want %d", len(loadedResults), len(pipelineResults))
	}

	// Step 8: 詳細な検証
	t.Log("Step 8: Detailed verification of loaded data")
	for i, loaded := range loadedResults {
		t.Logf("  Result %d:", i+1)
		t.Logf("    - ResultID: %s", loaded.ScanResult.ResultID)
		t.Logf("    - PullString: %s", loaded.ScanResult.PullString)
		t.Logf("    - Critical: %d, High: %d, Medium: %d, Low: %d",
			loaded.ScanResult.VulnTotalBySeverity.Critical,
			loaded.ScanResult.VulnTotalBySeverity.High,
			loaded.ScanResult.VulnTotalBySeverity.Medium,
			loaded.ScanResult.VulnTotalBySeverity.Low)
		t.Logf("    - Vulnerabilities count: %d", len(loaded.Vulnerabilities))

		// 脆弱性データの検証
		for j, vuln := range loaded.Vulnerabilities {
			if j < 3 { // 最初の3件だけログ出力
				t.Logf("      Vulnerability %d: %s (Severity: %d, Package: %s)",
					j+1, vuln.Vuln.Name, vuln.Vuln.Severity, vuln.Package.Name)
			}
		}
	}

	t.Log("✅ Pipeline to SQLite walkthrough completed successfully!")
}

// TestRuntimeToSQLiteWalkthrough は、モックサーバーからランタイムデータを取得してSQLiteに保存するまでの全フローをテスト
func TestRuntimeToSQLiteWalkthrough(t *testing.T) {
	// Step 1: モックサーバーのセットアップ
	t.Log("Step 1: Setting up mock server")
	mockConfig := testutil.DefaultMockServerConfig()
	mockConfig.RuntimePageCount = 2 // 2ページ分のデータを返す
	server := testutil.NewMockServer(mockConfig)
	defer server.Close()
	t.Logf("Mock server started at: %s", server.URL)

	// Step 2: Sysdig APIクライアントの作成
	t.Log("Step 2: Creating Sysdig API client")
	client := sysdig.NewClient(server.URL, "test-token")
	if client == nil {
		t.Fatal("Failed to create Sysdig client")
	}

	// Step 3: ランタイムスキャン結果の取得
	t.Log("Step 3: Fetching runtime scan results")
	runtimeResults, err := client.ListRuntimeResults()
	if err != nil {
		t.Fatalf("Failed to fetch runtime results: %v", err)
	}
	t.Logf("Fetched %d runtime scan results", len(runtimeResults))

	if len(runtimeResults) == 0 {
		t.Fatal("Expected at least 1 runtime result, got 0")
	}

	// Step 4: 各スキャン結果の詳細な脆弱性情報を取得
	t.Log("Step 4: Fetching detailed vulnerability information for each scan result")
	vulnerabilities := make(map[string][]sysdig.Vulnerability)

	for _, result := range runtimeResults {
		assetType := "unknown"
		if scope, ok := result.Scope["asset.type"]; ok {
			if at, ok := scope.(string); ok {
				assetType = at
			}
		}

		t.Logf("  - Fetching vulnerabilities for result: %s (asset: %s, type: %s)",
			result.ResultID, result.MainAssetName, assetType)
		vulns, err := client.GetScanResultVulnerabilities(result.ResultID)
		if err != nil {
			t.Logf("    Warning: Failed to fetch vulnerabilities for %s: %v", result.ResultID, err)
			vulnerabilities[result.ResultID] = []sysdig.Vulnerability{}
			continue
		}
		vulnerabilities[result.ResultID] = vulns
		t.Logf("    Found %d vulnerabilities", len(vulns))
	}

	// Step 5: SQLiteキャッシュの作成
	t.Log("Step 5: Creating SQLite cache")
	tempFile := filepath.Join(t.TempDir(), "runtime_walkthrough.db")
	sqliteCache, err := cache.NewSQLiteCache(tempFile)
	if err != nil {
		t.Fatalf("Failed to create SQLite cache: %v", err)
	}
	defer sqliteCache.Close()
	t.Logf("SQLite cache created at: %s", tempFile)

	// Step 6: スキャン結果と脆弱性をSQLiteに保存
	t.Log("Step 6: Saving scan results and vulnerabilities to SQLite")
	err = sqliteCache.SaveScanResults("runtime", runtimeResults, vulnerabilities)
	if err != nil {
		t.Fatalf("Failed to save scan results: %v", err)
	}
	t.Logf("Successfully saved %d scan results with their vulnerabilities", len(runtimeResults))

	// Step 7: 保存したデータを検証（ロードして確認）
	t.Log("Step 7: Verifying saved data by loading from SQLite")
	loadedResults, err := sqliteCache.LoadScanResults("runtime", 30)
	if err != nil {
		t.Fatalf("Failed to load scan results: %v", err)
	}
	t.Logf("Loaded %d scan results from SQLite", len(loadedResults))

	if len(loadedResults) != len(runtimeResults) {
		t.Errorf("Loaded results count mismatch: got %d, want %d", len(loadedResults), len(runtimeResults))
	}

	// Step 8: 詳細な検証
	t.Log("Step 8: Detailed verification of loaded data")
	for i, loaded := range loadedResults {
		t.Logf("  Result %d:", i+1)
		t.Logf("    - ResultID: %s", loaded.ScanResult.ResultID)
		t.Logf("    - MainAssetName: %s", loaded.ScanResult.MainAssetName)

		// asset.typeの取得
		if scope, ok := loaded.ScanResult.Scope["asset.type"]; ok {
			if at, ok := scope.(string); ok {
				t.Logf("    - AssetType: %s", at)
			}
		}

		t.Logf("    - Critical: %d, High: %d, Medium: %d, Low: %d",
			loaded.ScanResult.VulnTotalBySeverity.Critical,
			loaded.ScanResult.VulnTotalBySeverity.High,
			loaded.ScanResult.VulnTotalBySeverity.Medium,
			loaded.ScanResult.VulnTotalBySeverity.Low)
		t.Logf("    - Vulnerabilities count: %d", len(loaded.Vulnerabilities))

		// 脆弱性データの検証
		for j, vuln := range loaded.Vulnerabilities {
			if j < 3 { // 最初の3件だけログ出力
				t.Logf("      Vulnerability %d: %s (Severity: %d, Package: %s)",
					j+1, vuln.Vuln.Name, vuln.Vuln.Severity, vuln.Package.Name)
			}
		}
	}

	t.Log("✅ Runtime to SQLite walkthrough completed successfully!")
}

// TestSameDatabaseMultipleScanTypesWalkthrough は、1つのデータベースファイルに複数のscan_type（pipeline/runtime）を保存できることを確認
// 注: 実運用では pipeline_vulnerabilities.db と runtime_vulnerabilities.db を別々に使用することを推奨
func TestSameDatabaseMultipleScanTypesWalkthrough(t *testing.T) {
	t.Log("=== Same Database Multiple Scan Types Walkthrough ===")

	// Step 1: モックサーバーのセットアップ
	t.Log("Step 1: Setting up mock server")
	mockConfig := testutil.DefaultMockServerConfig()
	mockConfig.PipelinePageCount = 2
	mockConfig.RuntimePageCount = 2
	server := testutil.NewMockServer(mockConfig)
	defer server.Close()

	// Step 2: Sysdig APIクライアントの作成
	t.Log("Step 2: Creating Sysdig API client")
	client := sysdig.NewClient(server.URL, "test-token")

	// Step 3: SQLiteキャッシュの作成（共通データベース）
	t.Log("Step 3: Creating shared SQLite cache")
	tempFile := filepath.Join(t.TempDir(), "combined_walkthrough.db")
	sqliteCache, err := cache.NewSQLiteCache(tempFile)
	if err != nil {
		t.Fatalf("Failed to create SQLite cache: %v", err)
	}
	defer sqliteCache.Close()

	// Step 4: パイプラインデータの取得と保存
	t.Log("Step 4: Processing pipeline data")
	pipelineResults, err := client.ListPipelineResultsWithDays(7)
	if err != nil {
		t.Fatalf("Failed to fetch pipeline results: %v", err)
	}
	t.Logf("  Fetched %d pipeline results", len(pipelineResults))

	pipelineVulns := make(map[string][]sysdig.Vulnerability)
	for _, result := range pipelineResults {
		vulns, err := client.GetScanResultVulnerabilities(result.ResultID)
		if err != nil {
			pipelineVulns[result.ResultID] = []sysdig.Vulnerability{}
			continue
		}
		pipelineVulns[result.ResultID] = vulns
	}

	err = sqliteCache.SaveScanResults("pipeline", pipelineResults, pipelineVulns)
	if err != nil {
		t.Fatalf("Failed to save pipeline results: %v", err)
	}
	t.Logf("  Saved %d pipeline results", len(pipelineResults))

	// Step 5: ランタイムデータの取得と保存
	t.Log("Step 5: Processing runtime data")
	runtimeResults, err := client.ListRuntimeResults()
	if err != nil {
		t.Fatalf("Failed to fetch runtime results: %v", err)
	}
	t.Logf("  Fetched %d runtime results", len(runtimeResults))

	runtimeVulns := make(map[string][]sysdig.Vulnerability)
	for _, result := range runtimeResults {
		vulns, err := client.GetScanResultVulnerabilities(result.ResultID)
		if err != nil {
			runtimeVulns[result.ResultID] = []sysdig.Vulnerability{}
			continue
		}
		runtimeVulns[result.ResultID] = vulns
	}

	err = sqliteCache.SaveScanResults("runtime", runtimeResults, runtimeVulns)
	if err != nil {
		t.Fatalf("Failed to save runtime results: %v", err)
	}
	t.Logf("  Saved %d runtime results", len(runtimeResults))

	// Step 6: データベースから両方のデータを読み込んで検証
	t.Log("Step 6: Verifying both pipeline and runtime data from database")

	loadedPipeline, err := sqliteCache.LoadScanResults("pipeline", 30)
	if err != nil {
		t.Fatalf("Failed to load pipeline results: %v", err)
	}
	t.Logf("  Loaded %d pipeline results", len(loadedPipeline))

	loadedRuntime, err := sqliteCache.LoadScanResults("runtime", 30)
	if err != nil {
		t.Fatalf("Failed to load runtime results: %v", err)
	}
	t.Logf("  Loaded %d runtime results", len(loadedRuntime))

	// Step 7: データの整合性チェック
	t.Log("Step 7: Data integrity check")
	if len(loadedPipeline) != len(pipelineResults) {
		t.Errorf("Pipeline count mismatch: got %d, want %d", len(loadedPipeline), len(pipelineResults))
	}
	if len(loadedRuntime) != len(runtimeResults) {
		t.Errorf("Runtime count mismatch: got %d, want %d", len(loadedRuntime), len(runtimeResults))
	}

	// 統計情報の表示
	t.Log("Step 8: Summary statistics")
	totalPipelineVulns := 0
	for _, result := range loadedPipeline {
		totalPipelineVulns += len(result.Vulnerabilities)
	}
	totalRuntimeVulns := 0
	for _, result := range loadedRuntime {
		totalRuntimeVulns += len(result.Vulnerabilities)
	}

	t.Logf("  Pipeline: %d scan results, %d total vulnerabilities", len(loadedPipeline), totalPipelineVulns)
	t.Logf("  Runtime: %d scan results, %d total vulnerabilities", len(loadedRuntime), totalRuntimeVulns)
	t.Logf("  Database file: %s", tempFile)

	t.Log("✅ Same database multiple scan types walkthrough completed successfully!")
	t.Log("Note: In production, use separate DB files (pipeline_vulnerabilities.db and runtime_vulnerabilities.db)")
}
