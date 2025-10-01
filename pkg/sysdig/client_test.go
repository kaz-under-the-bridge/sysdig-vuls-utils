package sysdig

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kaz-under-the-bridge/sysdig-vuls-utils/internal/testutil"
)

// TestNewClient tests the NewClient constructor
func TestNewClient(t *testing.T) {
	tests := []struct {
		name      string
		baseURL   string
		apiToken  string
		wantError bool
	}{
		{
			name:      "valid client creation",
			baseURL:   "https://us2.app.sysdig.com",
			apiToken:  "test-token-123",
			wantError: false,
		},
		{
			name:      "empty base URL",
			baseURL:   "",
			apiToken:  "test-token-123",
			wantError: false, // baseURLが空でもクライアント作成は成功する
		},
		{
			name:      "empty API token",
			baseURL:   "https://us2.app.sysdig.com",
			apiToken:  "",
			wantError: false, // tokenが空でもクライアント作成は成功する（API呼び出し時にエラー）
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(tt.baseURL, tt.apiToken)
			if client == nil && !tt.wantError {
				t.Errorf("NewClient() returned nil, want non-nil client")
			}
			if client != nil {
				if client.baseURL != tt.baseURL {
					t.Errorf("NewClient() baseURL = %v, want %v", client.baseURL, tt.baseURL)
				}
				if client.apiToken != tt.apiToken {
					t.Errorf("NewClient() apiToken = %v, want %v", client.apiToken, tt.apiToken)
				}
				if client.httpClient == nil {
					t.Errorf("NewClient() httpClient is nil, want non-nil")
				}
			}
		})
	}
}

// TestGetFullScanResult tests the GetFullScanResult method
func TestGetFullScanResult(t *testing.T) {
	tests := []struct {
		name      string
		resultID  string
		setupMock func() string // Returns mock server URL
		wantError bool
		errorMsg  string
	}{
		{
			name:     "successful scan result retrieval",
			resultID: "scan-1234",
			setupMock: func() string {
				server := testutil.NewMockServer(testutil.DefaultMockServerConfig())
				return server.URL
			},
			wantError: false,
		},
		{
			name:     "scan result not found",
			resultID: "not-found-id",
			setupMock: func() string {
				config := testutil.DefaultMockServerConfig()
				config.NotFoundResultID = "not-found-id"
				server := testutil.NewMockServer(config)
				return server.URL
			},
			wantError: true,
			errorMsg:  "scan result not found",
		},
		{
			name:     "unauthorized request",
			resultID: "scan-1234",
			setupMock: func() string {
				server := testutil.NewMockServerUnauthorized()
				return server.URL
			},
			wantError: true,
			errorMsg:  "401",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverURL := tt.setupMock()
			client := NewClient(serverURL, "test-token")

			result, err := client.GetFullScanResult(tt.resultID)

			if tt.wantError {
				if err == nil {
					t.Errorf("GetFullScanResult() error = nil, want error containing '%s'", tt.errorMsg)
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("GetFullScanResult() error = %v, want error containing '%s'", err, tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("GetFullScanResult() unexpected error = %v", err)
				}
				if result == nil {
					t.Errorf("GetFullScanResult() result is nil, want non-nil")
				}
				if result != nil {
					if result.Stage != "pipeline" {
						t.Errorf("GetFullScanResult() stage = %v, want 'pipeline'", result.Stage)
					}
					if result.AssetType != "containerImage" {
						t.Errorf("GetFullScanResult() assetType = %v, want 'containerImage'", result.AssetType)
					}
					if len(result.Packages) == 0 {
						t.Errorf("GetFullScanResult() packages is empty, want non-empty")
					}
					if len(result.Vulnerabilities) == 0 {
						t.Errorf("GetFullScanResult() vulnerabilities is empty, want non-empty")
					}
				}
			}
		})
	}
}

// TestGetScanResultVulnerabilities tests the GetScanResultVulnerabilities method
func TestGetScanResultVulnerabilities(t *testing.T) {
	tests := []struct {
		name      string
		resultID  string
		setupMock func() string
		wantError bool
		minVulns  int // 最低限期待される脆弱性の数
	}{
		{
			name:     "successful vulnerability retrieval",
			resultID: "scan-1234",
			setupMock: func() string {
				server := testutil.NewMockServer(testutil.DefaultMockServerConfig())
				return server.URL
			},
			wantError: false,
			minVulns:  1,
		},
		{
			name:     "scan result not found",
			resultID: "not-found-id",
			setupMock: func() string {
				config := testutil.DefaultMockServerConfig()
				config.NotFoundResultID = "not-found-id"
				server := testutil.NewMockServer(config)
				return server.URL
			},
			wantError: true,
			minVulns:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverURL := tt.setupMock()
			client := NewClient(serverURL, "test-token")

			vulns, err := client.GetScanResultVulnerabilities(tt.resultID)

			if tt.wantError {
				if err == nil {
					t.Errorf("GetScanResultVulnerabilities() error = nil, want error")
				}
			} else {
				if err != nil {
					t.Errorf("GetScanResultVulnerabilities() unexpected error = %v", err)
				}
				if len(vulns) < tt.minVulns {
					t.Errorf("GetScanResultVulnerabilities() got %d vulnerabilities, want at least %d", len(vulns), tt.minVulns)
				}

				// 脆弱性データの検証
				for _, vuln := range vulns {
					if vuln.ID == "" {
						t.Errorf("GetScanResultVulnerabilities() vulnerability ID is empty")
					}
					if vuln.Vuln.Name == "" {
						t.Errorf("GetScanResultVulnerabilities() vulnerability name is empty")
					}
					if vuln.Package.Name == "" {
						t.Errorf("GetScanResultVulnerabilities() package name is empty")
					}
					// Severityの範囲チェック（1-5: low, medium, high, critical, negligible）
					if vuln.Vuln.Severity < 1 || vuln.Vuln.Severity > 5 {
						t.Errorf("GetScanResultVulnerabilities() invalid severity %d for %s", vuln.Vuln.Severity, vuln.ID)
					}
				}
			}
		})
	}
}

// TestListPipelineResultsWithDays tests the ListPipelineResultsWithDays method
func TestListPipelineResultsWithDays(t *testing.T) {
	tests := []struct {
		name        string
		days        int
		setupMock   func() string
		wantError   bool
		minResults  int
		checkPaging bool
	}{
		{
			name: "successful pipeline results retrieval with pagination",
			days: 7,
			setupMock: func() string {
				config := testutil.DefaultMockServerConfig()
				config.PipelinePageCount = 2
				server := testutil.NewMockServer(config)
				return server.URL
			},
			wantError:   false,
			minResults:  1,
			checkPaging: true,
		},
		{
			name: "unauthorized access",
			days: 7,
			setupMock: func() string {
				server := testutil.NewMockServerUnauthorized()
				return server.URL
			},
			wantError:   true,
			minResults:  0,
			checkPaging: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverURL := tt.setupMock()
			client := NewClient(serverURL, "test-token")

			results, err := client.ListPipelineResultsWithDays(tt.days)

			if tt.wantError {
				if err == nil {
					t.Errorf("ListPipelineResults() error = nil, want error")
				}
			} else {
				if err != nil {
					t.Errorf("ListPipelineResults() unexpected error = %v", err)
				}
				if len(results) < tt.minResults {
					t.Errorf("ListPipelineResults() got %d results, want at least %d", len(results), tt.minResults)
				}

				// 結果データの検証
				for _, result := range results {
					if result.ResultID == "" {
						t.Errorf("ListPipelineResults() result ID is empty")
					}
					if result.PullString == "" {
						t.Errorf("ListPipelineResults() pull string is empty")
					}
				}
			}
		})
	}
}

// TestListPipelineResultsWithFilter tests the ListPipelineResultsWithFilter method
func TestListPipelineResultsWithFilter(t *testing.T) {
	tests := []struct {
		name       string
		days       int
		filter     string
		setupMock  func() string
		wantError  bool
		minResults int
	}{
		{
			name:   "successful filtered pipeline results",
			days:   7,
			filter: "nginx",
			setupMock: func() string {
				server := testutil.NewMockServer(testutil.DefaultMockServerConfig())
				return server.URL
			},
			wantError:  false,
			minResults: 1,
		},
		{
			name:   "no filter specified",
			days:   7,
			filter: "",
			setupMock: func() string {
				server := testutil.NewMockServer(testutil.DefaultMockServerConfig())
				return server.URL
			},
			wantError:  false,
			minResults: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverURL := tt.setupMock()
			client := NewClient(serverURL, "test-token")

			results, err := client.ListPipelineResultsWithFilter(tt.days, tt.filter)

			if tt.wantError {
				if err == nil {
					t.Errorf("ListPipelineResultsWithFilter() error = nil, want error")
				}
			} else {
				if err != nil {
					t.Errorf("ListPipelineResultsWithFilter() unexpected error = %v", err)
				}
				if len(results) < tt.minResults {
					t.Errorf("ListPipelineResultsWithFilter() got %d results, want at least %d", len(results), tt.minResults)
				}
			}
		})
	}
}

// TestListRuntimeResults tests the ListRuntimeResults method
func TestListRuntimeResults(t *testing.T) {
	tests := []struct {
		name       string
		setupMock  func() string
		wantError  bool
		minResults int
	}{
		{
			name: "successful runtime results retrieval",
			setupMock: func() string {
				config := testutil.DefaultMockServerConfig()
				config.RuntimePageCount = 2
				server := testutil.NewMockServer(config)
				return server.URL
			},
			wantError:  false,
			minResults: 1,
		},
		{
			name: "unauthorized access",
			setupMock: func() string {
				server := testutil.NewMockServerUnauthorized()
				return server.URL
			},
			wantError:  true,
			minResults: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverURL := tt.setupMock()
			client := NewClient(serverURL, "test-token")

			results, err := client.ListRuntimeResults()

			if tt.wantError {
				if err == nil {
					t.Errorf("ListRuntimeResults() error = nil, want error")
				}
			} else {
				if err != nil {
					t.Errorf("ListRuntimeResults() unexpected error = %v", err)
				}
				if len(results) < tt.minResults {
					t.Errorf("ListRuntimeResults() got %d results, want at least %d", len(results), tt.minResults)
				}

				// 結果データの検証
				for _, result := range results {
					if result.ResultID == "" {
						t.Errorf("ListRuntimeResults() result ID is empty")
					}
					if result.MainAssetName == "" {
						t.Errorf("ListRuntimeResults() main asset name is empty")
					}
				}
			}
		})
	}
}

// TestListAcceptedRisks tests the ListAcceptedRisks method
func TestListAcceptedRisks(t *testing.T) {
	tests := []struct {
		name       string
		setupMock  func() string
		wantError  bool
		minResults int
	}{
		{
			name: "successful accepted risks retrieval",
			setupMock: func() string {
				config := testutil.DefaultMockServerConfig()
				config.AcceptedRisksPageCount = 2
				server := testutil.NewMockServer(config)
				return server.URL
			},
			wantError:  false,
			minResults: 1,
		},
		{
			name: "rate limit error",
			setupMock: func() string {
				server := testutil.NewMockServerWithRateLimit()
				return server.URL
			},
			wantError:  true,
			minResults: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverURL := tt.setupMock()
			client := NewClient(serverURL, "test-token")

			risks, err := client.ListAcceptedRisks()

			if tt.wantError {
				if err == nil {
					t.Errorf("ListAcceptedRisks() error = nil, want error")
				}
			} else {
				if err != nil {
					t.Errorf("ListAcceptedRisks() unexpected error = %v", err)
				}
				if len(risks) < tt.minResults {
					t.Errorf("ListAcceptedRisks() got %d risks, want at least %d", len(risks), tt.minResults)
				}

				// リスクデータの検証
				for _, risk := range risks {
					if risk.EntityValue == "" {
						t.Errorf("ListAcceptedRisks() risk EntityValue is empty")
					}
					if risk.ExpirationDate == "" {
						t.Errorf("ListAcceptedRisks() risk ExpirationDate is empty")
					}
				}
			}
		})
	}
}

// TestSeverityStringToInt tests the severityStringToInt helper function
func TestSeverityStringToInt(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		want     int
	}{
		{"critical severity", "critical", 4},
		{"high severity", "high", 3},
		{"medium severity", "medium", 2},
		{"low severity", "low", 1},
		{"negligible severity", "negligible", 5},
		{"uppercase critical", "CRITICAL", 4},
		{"mixed case high", "High", 3},
		{"unknown severity", "unknown", 0},
		{"empty string", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := severityStringToInt(tt.severity)
			if got != tt.want {
				t.Errorf("severityStringToInt(%q) = %d, want %d", tt.severity, got, tt.want)
			}
		})
	}
}

// TestCreateAcceptedRisk tests the CreateAcceptedRisk method
func TestCreateAcceptedRisk(t *testing.T) {
	tests := []struct {
		name           string
		entityValue    string
		expirationDays int
		description    string
		setupMock      func() string
		wantError      bool
	}{
		{
			name:           "successful risk acceptance creation",
			entityValue:    "CVE-2023-0286",
			expirationDays: 90,
			description:    "Test risk acceptance",
			setupMock: func() string {
				server := testutil.NewMockServer(testutil.DefaultMockServerConfig())
				return server.URL
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverURL := tt.setupMock()
			client := NewClient(serverURL, "test-token")

			err := client.CreateAcceptedRisk(tt.entityValue, tt.expirationDays, tt.description)

			if tt.wantError {
				if err == nil {
					t.Errorf("CreateAcceptedRisk() error = nil, want error")
				}
			} else {
				if err != nil {
					t.Errorf("CreateAcceptedRisk() unexpected error = %v", err)
				}
			}
		})
	}
}

// TestClientWithInvalidBaseURL tests client behavior with invalid base URL
func TestClientWithInvalidBaseURL(t *testing.T) {
	client := NewClient("http://invalid-url-that-does-not-exist.local", "test-token")

	_, err := client.GetFullScanResult("scan-1234")
	if err == nil {
		t.Errorf("Expected error when using invalid base URL, got nil")
	}
}

// TestAuthenticationWithMockServer tests proper authentication header passing
func TestAuthenticationWithMockServer(t *testing.T) {
	validToken := "valid-test-token"
	server := testutil.NewMockServerWithAuth(validToken)
	defer server.Close()

	tests := []struct {
		name      string
		token     string
		wantError bool
	}{
		{
			name:      "valid token",
			token:     validToken,
			wantError: false,
		},
		{
			name:      "invalid token",
			token:     "invalid-token",
			wantError: true,
		},
		{
			name:      "empty token",
			token:     "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(server.URL, tt.token)
			_, err := client.GetFullScanResult("scan-1234")

			if tt.wantError && err == nil {
				t.Errorf("Expected error with token %q, got nil", tt.token)
			}
			if !tt.wantError && err != nil {
				t.Errorf("Unexpected error with valid token: %v", err)
			}
		})
	}
}

// TestPaginationHandling tests proper pagination handling
func TestPaginationHandling(t *testing.T) {
	t.Run("pipeline results pagination", func(t *testing.T) {
		config := testutil.DefaultMockServerConfig()
		config.PipelinePageCount = 3
		server := testutil.NewMockServer(config)
		defer server.Close()

		client := NewClient(server.URL, "test-token")
		results, err := client.ListPipelineResultsWithDays(7)

		if err != nil {
			t.Errorf("ListPipelineResults() unexpected error = %v", err)
		}

		// 複数ページから結果を取得できることを確認
		if len(results) == 0 {
			t.Errorf("ListPipelineResults() returned empty results, expected paginated data")
		}
	})

	t.Run("runtime results pagination", func(t *testing.T) {
		config := testutil.DefaultMockServerConfig()
		config.RuntimePageCount = 3
		server := testutil.NewMockServer(config)
		defer server.Close()

		client := NewClient(server.URL, "test-token")
		results, err := client.ListRuntimeResults()

		if err != nil {
			t.Errorf("ListRuntimeResults() unexpected error = %v", err)
		}

		if len(results) == 0 {
			t.Errorf("ListRuntimeResults() returned empty results, expected paginated data")
		}
	})
}

// Benchmark tests for performance measurement

func BenchmarkGetFullScanResult(b *testing.B) {
	server := testutil.NewMockServer(testutil.DefaultMockServerConfig())
	defer server.Close()

	client := NewClient(server.URL, "test-token")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := client.GetFullScanResult("scan-1234")
		if err != nil {
			b.Fatalf("GetFullScanResult() error = %v", err)
		}
	}
}

func BenchmarkGetScanResultVulnerabilities(b *testing.B) {
	server := testutil.NewMockServer(testutil.DefaultMockServerConfig())
	defer server.Close()

	client := NewClient(server.URL, "test-token")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := client.GetScanResultVulnerabilities("scan-1234")
		if err != nil {
			b.Fatalf("GetScanResultVulnerabilities() error = %v", err)
		}
	}
}

func BenchmarkSeverityStringToInt(b *testing.B) {
	severities := []string{"critical", "high", "medium", "low", "negligible"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = severityStringToInt(severities[i%len(severities)])
	}
}

// Example tests for documentation

func ExampleClient_GetFullScanResult() {
	client := NewClient("https://us2.app.sysdig.com", "your-api-token")
	result, err := client.GetFullScanResult("scan-result-id")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Scan result for %s\n", result.Metadata.PullString)
}

func ExampleClient_GetScanResultVulnerabilities() {
	client := NewClient("https://us2.app.sysdig.com", "your-api-token")
	vulns, err := client.GetScanResultVulnerabilities("scan-result-id")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Found %d vulnerabilities\n", len(vulns))
}

func ExampleClient_ListPipelineResultsWithDays() {
	client := NewClient("https://us2.app.sysdig.com", "your-api-token")
	results, err := client.ListPipelineResultsWithDays(7) // Last 7 days
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Found %d pipeline scan results\n", len(results))
}
