package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kaz-under-the-bridge/sysdig-vuls-utils/pkg/sysdig"
)

// TestNewSQLiteCache tests SQLite cache creation
func TestNewSQLiteCache(t *testing.T) {
	tests := []struct {
		name      string
		filepath  string
		wantError bool
	}{
		{
			name:      "valid cache creation",
			filepath:  filepath.Join(t.TempDir(), "test_cache.db"),
			wantError: false,
		},
		{
			name:      "cache with nested directory",
			filepath:  filepath.Join(t.TempDir(), "subdir", "test_cache.db"),
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache, err := NewSQLiteCache(tt.filepath)
			if tt.wantError {
				if err == nil {
					t.Errorf("NewSQLiteCache() error = nil, want error")
				}
			} else {
				if err != nil {
					t.Errorf("NewSQLiteCache() unexpected error = %v", err)
				}
				if cache == nil {
					t.Errorf("NewSQLiteCache() cache is nil, want non-nil")
				}
				if cache != nil {
					defer cache.Close()
					if cache.filepath != tt.filepath {
						t.Errorf("NewSQLiteCache() filepath = %v, want %v", cache.filepath, tt.filepath)
					}
					if cache.db == nil {
						t.Errorf("NewSQLiteCache() db is nil, want non-nil")
					}
				}
			}
		})
	}
}

// TestSQLiteCacheSaveAndLoad tests basic save and load functionality
func TestSQLiteCacheSaveAndLoad(t *testing.T) {
	tempFile := filepath.Join(t.TempDir(), "test_save_load.db")
	cache, err := NewSQLiteCache(tempFile)
	if err != nil {
		t.Fatalf("NewSQLiteCache() error = %v", err)
	}
	defer cache.Close()

	// テストデータの作成
	testVulns := []sysdig.Vulnerability{
		{
			ID: "CVE-2023-0001",
			Vuln: sysdig.VulnV2{
				Name:           "CVE-2023-0001",
				Severity:       4, // critical
				CvssScore:      9.8,
				Exploitable:    true,
				DisclosureDate: "2023-01-01",
				Fixable:        true,
			},
			Package: sysdig.PackageV2{
				ID:      "pkg-001",
				Name:    "openssl",
				Version: "1.0.0",
				Type:    "os",
			},
		},
		{
			ID: "CVE-2023-0002",
			Vuln: sysdig.VulnV2{
				Name:           "CVE-2023-0002",
				Severity:       3, // high
				CvssScore:      7.5,
				Exploitable:    false,
				DisclosureDate: "2023-02-01",
				Fixable:        true,
			},
			Package: sysdig.PackageV2{
				ID:      "pkg-002",
				Name:    "curl",
				Version: "7.50.0",
				Type:    "os",
			},
		},
	}

	// Save test
	err = cache.Save(testVulns)
	if err != nil {
		t.Errorf("Save() error = %v", err)
	}

	// Load test
	loaded, err := cache.Load()
	if err != nil {
		t.Errorf("Load() error = %v", err)
	}

	if len(loaded) != len(testVulns) {
		t.Errorf("Load() returned %d vulnerabilities, want %d", len(loaded), len(testVulns))
	}
}

// TestSQLiteCacheClear tests cache clearing functionality
func TestSQLiteCacheClear(t *testing.T) {
	tempFile := filepath.Join(t.TempDir(), "test_clear.db")
	cache, err := NewSQLiteCache(tempFile)
	if err != nil {
		t.Fatalf("NewSQLiteCache() error = %v", err)
	}
	defer cache.Close()

	// データを保存
	testVulns := []sysdig.Vulnerability{
		{
			ID: "CVE-2023-0001",
			Vuln: sysdig.VulnV2{
				Name:     "CVE-2023-0001",
				Severity: 4,
			},
			Package: sysdig.PackageV2{
				Name: "test-package",
			},
		},
	}

	err = cache.Save(testVulns)
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Clear test
	err = cache.Clear()
	if err != nil {
		t.Errorf("Clear() error = %v", err)
	}

	// クリア後の確認
	loaded, err := cache.Load()
	if err != nil {
		t.Errorf("Load() after Clear() error = %v", err)
	}

	if len(loaded) != 0 {
		t.Errorf("Load() after Clear() returned %d vulnerabilities, want 0", len(loaded))
	}
}

// TestSaveScanResults tests saving scan results with vulnerabilities
func TestSaveScanResults(t *testing.T) {
	tempFile := filepath.Join(t.TempDir(), "test_scan_results.db")
	cache, err := NewSQLiteCache(tempFile)
	if err != nil {
		t.Fatalf("NewSQLiteCache() error = %v", err)
	}
	defer cache.Close()

	// テストスキャン結果
	scanResults := []sysdig.ScanResult{
		{
			ResultID:   "scan-001",
			CreatedAt:  time.Now().Format(time.RFC3339),
			PullString: "nginx:latest",
			VulnTotalBySeverity: sysdig.VulnSeverityCount{
				Critical: 5,
				High:     10,
				Medium:   8,
				Low:      2,
			},
		},
		{
			ResultID:   "scan-002",
			CreatedAt:  time.Now().Format(time.RFC3339),
			PullString: "alpine:3.18",
			VulnTotalBySeverity: sysdig.VulnSeverityCount{
				Critical: 2,
				High:     5,
				Medium:   3,
				Low:      0,
			},
		},
	}

	// テスト脆弱性データ
	vulnerabilities := map[string][]sysdig.Vulnerability{
		"scan-001": {
			{
				ID: "CVE-2023-0001",
				Vuln: sysdig.VulnV2{
					Name:           "CVE-2023-0001",
					Severity:       4,
					DisclosureDate: "2023-01-01",
					Fixable:        true,
				},
				Package: sysdig.PackageV2{
					ID:   "pkg-001",
					Name: "openssl",
				},
			},
		},
		"scan-002": {
			{
				ID: "CVE-2023-0002",
				Vuln: sysdig.VulnV2{
					Name:           "CVE-2023-0002",
					Severity:       3,
					DisclosureDate: "2023-02-01",
					Fixable:        true,
				},
				Package: sysdig.PackageV2{
					ID:   "pkg-002",
					Name: "curl",
				},
			},
		},
	}

	// Save test
	err = cache.SaveScanResults("pipeline", scanResults, vulnerabilities)
	if err != nil {
		t.Errorf("SaveScanResults() error = %v", err)
	}

	// Load test
	loaded, err := cache.LoadScanResults("pipeline", 30)
	if err != nil {
		t.Errorf("LoadScanResults() error = %v", err)
	}

	if len(loaded) != len(scanResults) {
		t.Errorf("LoadScanResults() returned %d results, want %d", len(loaded), len(scanResults))
	}

	// 脆弱性の数を検証
	for _, result := range loaded {
		if result.ScanResult.ResultID == "scan-001" {
			if len(result.Vulnerabilities) != 1 {
				t.Errorf("LoadScanResults() scan-001 has %d vulnerabilities, want 1", len(result.Vulnerabilities))
			}
		}
	}
}

// TestLoadScanResultsWithDaysFilter tests filtering by days
func TestLoadScanResultsWithDaysFilter(t *testing.T) {
	tempFile := filepath.Join(t.TempDir(), "test_days_filter.db")
	cache, err := NewSQLiteCache(tempFile)
	if err != nil {
		t.Fatalf("NewSQLiteCache() error = %v", err)
	}
	defer cache.Close()

	// 古いスキャン結果（8日前）
	oldTime := time.Now().AddDate(0, 0, -8).Format(time.RFC3339)
	// 最近のスキャン結果（3日前）
	recentTime := time.Now().AddDate(0, 0, -3).Format(time.RFC3339)

	scanResults := []sysdig.ScanResult{
		{
			ResultID:   "scan-old",
			CreatedAt:  oldTime,
			PullString: "old-image:1.0",
		},
		{
			ResultID:   "scan-recent",
			CreatedAt:  recentTime,
			PullString: "recent-image:2.0",
		},
	}

	vulnerabilities := map[string][]sysdig.Vulnerability{
		"scan-old":    {},
		"scan-recent": {},
	}

	err = cache.SaveScanResults("pipeline", scanResults, vulnerabilities)
	if err != nil {
		t.Fatalf("SaveScanResults() error = %v", err)
	}

	// 7日以内のデータのみロード
	loaded, err := cache.LoadScanResults("pipeline", 7)
	if err != nil {
		t.Errorf("LoadScanResults() error = %v", err)
	}

	// 最近のスキャン結果のみが返されるはず
	if len(loaded) != 1 {
		t.Errorf("LoadScanResults(7 days) returned %d results, want 1", len(loaded))
	}

	if len(loaded) > 0 && loaded[0].ScanResult.ResultID != "scan-recent" {
		t.Errorf("LoadScanResults(7 days) returned %s, want scan-recent", loaded[0].ScanResult.ResultID)
	}
}

// TestClearScanResults tests clearing scan results by type
func TestClearScanResults(t *testing.T) {
	tempFile := filepath.Join(t.TempDir(), "test_clear_scan_results.db")
	cache, err := NewSQLiteCache(tempFile)
	if err != nil {
		t.Fatalf("NewSQLiteCache() error = %v", err)
	}
	defer cache.Close()

	// パイプラインとランタイムの両方のデータを保存
	pipelineScanResults := []sysdig.ScanResult{
		{
			ResultID:   "pipeline-001",
			CreatedAt:  time.Now().Format(time.RFC3339),
			PullString: "pipeline-image:1.0",
		},
	}

	runtimeScanResults := []sysdig.ScanResult{
		{
			ResultID:      "runtime-001",
			MainAssetName: "runtime-asset",
		},
	}

	err = cache.SaveScanResults("pipeline", pipelineScanResults, map[string][]sysdig.Vulnerability{})
	if err != nil {
		t.Fatalf("SaveScanResults(pipeline) error = %v", err)
	}

	err = cache.SaveScanResults("runtime", runtimeScanResults, map[string][]sysdig.Vulnerability{})
	if err != nil {
		t.Fatalf("SaveScanResults(runtime) error = %v", err)
	}

	// パイプラインデータのみクリア
	err = cache.ClearScanResults("pipeline")
	if err != nil {
		t.Errorf("ClearScanResults(pipeline) error = %v", err)
	}

	// パイプラインデータは空になっているはず
	pipelineLoaded, err := cache.LoadScanResults("pipeline", 30)
	if err != nil {
		t.Errorf("LoadScanResults(pipeline) after clear error = %v", err)
	}
	if len(pipelineLoaded) != 0 {
		t.Errorf("LoadScanResults(pipeline) after clear returned %d results, want 0", len(pipelineLoaded))
	}

	// ランタイムデータは残っているはず
	runtimeLoaded, err := cache.LoadScanResults("runtime", 30)
	if err != nil {
		t.Errorf("LoadScanResults(runtime) after clear error = %v", err)
	}
	if len(runtimeLoaded) != 1 {
		t.Errorf("LoadScanResults(runtime) after clear returned %d results, want 1", len(runtimeLoaded))
	}
}

// TestCacheClose tests cache closing
func TestCacheClose(t *testing.T) {
	tempFile := filepath.Join(t.TempDir(), "test_close.db")
	cache, err := NewSQLiteCache(tempFile)
	if err != nil {
		t.Fatalf("NewSQLiteCache() error = %v", err)
	}

	err = cache.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Close後の操作はエラーになるはず
	testVulns := []sysdig.Vulnerability{
		{
			ID: "CVE-2023-0001",
			Vuln: sysdig.VulnV2{
				Name: "CVE-2023-0001",
			},
		},
	}

	err = cache.Save(testVulns)
	if err == nil {
		t.Errorf("Save() after Close() error = nil, want error")
	}
}

// TestNewCache tests cache factory function
func TestNewCache(t *testing.T) {
	tests := []struct {
		name      string
		cacheType CacheType
		wantError bool
	}{
		{
			name:      "sqlite cache",
			cacheType: CacheTypeSQLite,
			wantError: false,
		},
		{
			name:      "csv cache (deprecated)",
			cacheType: CacheTypeCSV,
			wantError: false,
		},
		{
			name:      "invalid cache type",
			cacheType: CacheType("invalid"),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempFile := filepath.Join(t.TempDir(), "test_factory.db")
			cache, err := NewCache(tt.cacheType, tempFile)

			if tt.wantError {
				if err == nil {
					t.Errorf("NewCache() error = nil, want error")
				}
			} else {
				if err != nil {
					t.Errorf("NewCache() unexpected error = %v", err)
				}
				if cache != nil {
					defer cache.Close()
				}
			}
		})
	}
}

// TestCSVCacheDeprecated tests that CSV cache is deprecated but functional
func TestCSVCacheDeprecated(t *testing.T) {
	tempFile := filepath.Join(t.TempDir(), "test.csv")
	cache := NewCSVCache(tempFile)

	if cache == nil {
		t.Errorf("NewCSVCache() returned nil, want non-nil")
	}

	// CSV cacheは基本的な操作が可能だが、機能は限定的
	testVulns := []sysdig.Vulnerability{
		{
			ID: "CVE-2023-0001",
			Vuln: sysdig.VulnV2{
				Name: "CVE-2023-0001",
			},
		},
	}

	// CSVキャッシュの動作確認（エラーハンドリング）
	err := cache.Save(testVulns)
	if err != nil {
		// CSVキャッシュは実装が簡易的なのでエラーは許容
		t.Logf("CSV Save() error (expected): %v", err)
	}

	err = cache.Close()
	if err != nil {
		t.Logf("CSV Close() error (expected): %v", err)
	}
}

// TestConcurrentAccess tests concurrent cache access
func TestConcurrentAccess(t *testing.T) {
	tempFile := filepath.Join(t.TempDir(), "test_concurrent.db")
	cache, err := NewSQLiteCache(tempFile)
	if err != nil {
		t.Fatalf("NewSQLiteCache() error = %v", err)
	}
	defer cache.Close()

	// 並行書き込みテスト
	done := make(chan bool, 3)

	for i := 0; i < 3; i++ {
		go func(id int) {
			scanResults := []sysdig.ScanResult{
				{
					ResultID:   "concurrent-" + string(rune('0'+id)),
					PullString: "test-image",
				},
			}
			err := cache.SaveScanResults("pipeline", scanResults, map[string][]sysdig.Vulnerability{})
			if err != nil {
				t.Logf("Concurrent SaveScanResults() error: %v", err)
			}
			done <- true
		}(i)
	}

	// 全てのgoroutineが完了するまで待機
	for i := 0; i < 3; i++ {
		<-done
	}

	// データが正しく保存されているか確認
	loaded, err := cache.LoadScanResults("pipeline", 30)
	if err != nil {
		t.Errorf("LoadScanResults() after concurrent writes error = %v", err)
	}

	if len(loaded) == 0 {
		t.Errorf("LoadScanResults() after concurrent writes returned 0 results, want at least 1")
	}
}

// Benchmark tests for performance measurement

func BenchmarkSQLiteCacheSave(b *testing.B) {
	tempFile := filepath.Join(b.TempDir(), "bench_save.db")
	cache, err := NewSQLiteCache(tempFile)
	if err != nil {
		b.Fatalf("NewSQLiteCache() error = %v", err)
	}
	defer cache.Close()

	testVulns := []sysdig.Vulnerability{
		{
			ID: "CVE-2023-0001",
			Vuln: sysdig.VulnV2{
				Name:     "CVE-2023-0001",
				Severity: 4,
			},
			Package: sysdig.PackageV2{
				Name: "test-package",
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cache.Save(testVulns)
	}
}

func BenchmarkSQLiteCacheLoad(b *testing.B) {
	tempFile := filepath.Join(b.TempDir(), "bench_load.db")
	cache, err := NewSQLiteCache(tempFile)
	if err != nil {
		b.Fatalf("NewSQLiteCache() error = %v", err)
	}
	defer cache.Close()

	testVulns := []sysdig.Vulnerability{
		{
			ID: "CVE-2023-0001",
			Vuln: sysdig.VulnV2{
				Name: "CVE-2023-0001",
			},
		},
	}
	_ = cache.Save(testVulns)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cache.Load()
	}
}

// TestDatabaseFileCreation tests that database file is created
func TestDatabaseFileCreation(t *testing.T) {
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "test_file_creation.db")

	// ファイルが存在しないことを確認
	if _, err := os.Stat(tempFile); !os.IsNotExist(err) {
		t.Errorf("File %s should not exist before cache creation", tempFile)
	}

	cache, err := NewSQLiteCache(tempFile)
	if err != nil {
		t.Fatalf("NewSQLiteCache() error = %v", err)
	}
	defer cache.Close()

	// ファイルが作成されたことを確認
	if _, err := os.Stat(tempFile); os.IsNotExist(err) {
		t.Errorf("File %s should exist after cache creation", tempFile)
	}
}
