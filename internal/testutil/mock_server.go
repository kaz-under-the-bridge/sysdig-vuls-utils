// Package testutil provides test fixtures and utilities for testing Sysdig API client.
package testutil

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
)

// MockServerConfig holds configuration for the mock server
type MockServerConfig struct {
	// PipelinePageCount controls how many pages to return for pipeline results
	PipelinePageCount int
	// RuntimePageCount controls how many pages to return for runtime results
	RuntimePageCount int
	// AcceptedRisksPageCount controls how many pages to return for accepted risks
	AcceptedRisksPageCount int
	// FullScanResultID is the result ID that will return a valid full scan result
	FullScanResultID string
	// NotFoundResultID is the result ID that will return 404
	NotFoundResultID string
	// UnauthorizedResponse controls whether to return 401 for all requests
	UnauthorizedResponse bool
	// RateLimitResponse controls whether to return 429 for all requests
	RateLimitResponse bool
}

// DefaultMockServerConfig returns a default configuration
func DefaultMockServerConfig() *MockServerConfig {
	return &MockServerConfig{
		PipelinePageCount:      2,
		RuntimePageCount:       2,
		AcceptedRisksPageCount: 2,
		FullScanResultID:       "scan-1234",
		NotFoundResultID:       "not-found-id",
		UnauthorizedResponse:   false,
		RateLimitResponse:      false,
	}
}

// NewMockServer creates a new HTTP test server that mocks Sysdig API endpoints
func NewMockServer(config *MockServerConfig) *httptest.Server {
	if config == nil {
		config = DefaultMockServerConfig()
	}

	// ページカウンター（リクエストごとにインクリメント）
	pipelinePageNum := 0
	runtimePageNum := 0
	acceptedRisksPageNum := 0

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 認証チェック
		if config.UnauthorizedResponse {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"message": "unauthorized"}`))
			return
		}

		// レート制限チェック
		if config.RateLimitResponse {
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"message": "rate limit exceeded"}`))
			return
		}

		// Authorization ヘッダーチェック
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"message": "missing authorization header"}`))
			return
		}

		// エンドポイントルーティング
		path := r.URL.Path

		switch {
		case strings.HasPrefix(path, "/secure/vulnerability/v1/pipeline-results"):
			handlePipelineResults(w, r, config, &pipelinePageNum)

		case strings.HasPrefix(path, "/secure/vulnerability/v1/runtime-results"):
			handleRuntimeResults(w, r, config, &runtimePageNum)

		case strings.HasPrefix(path, "/secure/vulnerability/v1/results/"):
			resultID := strings.TrimPrefix(path, "/secure/vulnerability/v1/results/")
			handleFullScanResult(w, r, config, resultID)

		case strings.HasPrefix(path, "/secure/scanning/v1/riskacceptances"):
			handleAcceptedRisks(w, r, config, &acceptedRisksPageNum)

		case strings.HasPrefix(path, "/secure/vulnerability/v1beta1/accepted-risks"):
			handleAcceptedRisks(w, r, config, &acceptedRisksPageNum)

		case strings.HasPrefix(path, "/accepted-risks"):
			handleAcceptedRisks(w, r, config, &acceptedRisksPageNum)

		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"message": "endpoint not found"}`))
		}
	})

	return httptest.NewServer(handler)
}

// handlePipelineResults handles /secure/vulnerability/v1/pipeline-results
func handlePipelineResults(w http.ResponseWriter, r *http.Request, config *MockServerConfig, pageNum *int) {
	w.Header().Set("Content-Type", "application/json")

	// クエリパラメータ確認
	_ = r.URL.Query().Get("cursor") // cursorは使用しないが、将来の実装のために残す
	filter := r.URL.Query().Get("filter")

	// フィルタが指定されている場合のテスト
	if filter != "" {
		// freeText in ("nginx") 形式をチェック
		if !strings.Contains(filter, "freeText") {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"message": "invalid filter parameter"}`))
			return
		}
	}

	*pageNum++

	// ページ数に応じて応答を返す
	if *pageNum < config.PipelinePageCount {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(PipelineResultsFixture()))
	} else {
		// 最後のページ（cursorなし）
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(PipelineResultsLastPageFixture()))
	}
}

// handleRuntimeResults handles /secure/vulnerability/v1/runtime-results
func handleRuntimeResults(w http.ResponseWriter, r *http.Request, config *MockServerConfig, pageNum *int) {
	w.Header().Set("Content-Type", "application/json")

	// クエリパラメータ確認
	_ = r.URL.Query().Get("cursor") // cursorは使用しないが、将来の実装のために残す
	filter := r.URL.Query().Get("filter")
	_ = r.URL.Query().Get("sort")  // sortは使用しないが、将来の実装のために残す
	_ = r.URL.Query().Get("order") // orderは使用しないが、将来の実装のために残す

	// フィルタが指定されている場合のテスト
	if filter != "" {
		// kubernetes.cluster.name="staging" 形式をチェック
		if !strings.Contains(filter, "=") {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"message": "invalid filter parameter"}`))
			return
		}
	}

	*pageNum++

	// ページ数に応じて応答を返す
	if *pageNum < config.RuntimePageCount {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(RuntimeResultsFixture()))
	} else {
		// 最後のページ（cursorなし）
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(RuntimeResultsLastPageFixture()))
	}
}

// handleFullScanResult handles /secure/vulnerability/v1/results/{resultId}
func handleFullScanResult(w http.ResponseWriter, r *http.Request, config *MockServerConfig, resultID string) {
	w.Header().Set("Content-Type", "application/json")

	if resultID == config.NotFoundResultID {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(FullScanResultNotFoundFixture()))
		return
	}

	if resultID == config.FullScanResultID || resultID == "scan-1234" || resultID == "runtime-1234" {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(FullScanResultFixture()))
		return
	}

	// その他のresultIDの場合もデフォルトのfixtureを返す
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(FullScanResultFixture()))
}

// handleAcceptedRisks handles /secure/scanning/v1/riskacceptances
func handleAcceptedRisks(w http.ResponseWriter, r *http.Request, config *MockServerConfig, pageNum *int) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodPost {
		// POST request: create accepted risk
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id": "risk-accept-new", "status": "active"}`))
		return
	}

	// GET request: list accepted risks
	*pageNum++

	if *pageNum < config.AcceptedRisksPageCount {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(AcceptedRisksFixture()))
	} else {
		// 最後のページ（cursorなし）
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(AcceptedRisksLastPageFixture()))
	}
}

// NewMockServerWithAuth creates a mock server that requires valid authorization
func NewMockServerWithAuth(token string) *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		expectedAuth := fmt.Sprintf("Bearer %s", token)

		if authHeader != expectedAuth {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"message": "invalid token"}`))
			return
		}

		// 正しいトークンの場合は通常のレスポンス
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		switch {
		case strings.HasPrefix(path, "/secure/vulnerability/v1/pipeline-results"):
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(PipelineResultsLastPageFixture()))

		case strings.HasPrefix(path, "/secure/vulnerability/v1/runtime-results"):
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(RuntimeResultsLastPageFixture()))

		case strings.HasPrefix(path, "/secure/vulnerability/v1/results/"):
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(FullScanResultFixture()))

		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"message": "endpoint not found"}`))
		}
	})

	return httptest.NewServer(handler)
}

// NewMockServerWithRateLimit creates a mock server that returns rate limit errors
func NewMockServerWithRateLimit() *httptest.Server {
	config := DefaultMockServerConfig()
	config.RateLimitResponse = true
	return NewMockServer(config)
}

// NewMockServerUnauthorized creates a mock server that always returns 401
func NewMockServerUnauthorized() *httptest.Server {
	config := DefaultMockServerConfig()
	config.UnauthorizedResponse = true
	return NewMockServer(config)
}
