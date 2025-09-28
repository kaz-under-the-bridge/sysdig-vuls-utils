package sysdig

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient(t *testing.T) {
	client := NewClient("https://api.example.com", "test-token")

	if client == nil {
		t.Fatal("Expected client to be created")
	}

	if client.baseURL != "https://api.example.com" {
		t.Errorf("Expected baseURL to be https://api.example.com, got %s", client.baseURL)
	}

	if client.apiToken != "test-token" {
		t.Errorf("Expected apiToken to be test-token, got %s", client.apiToken)
	}
}

func TestListVulnerabilitiesWithFilters(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.URL.Path != "/api/secure/v1/vulnerabilities" {
			t.Errorf("Expected path /api/secure/v1/vulnerabilities, got %s", r.URL.Path)
		}

		// Check query parameters
		query := r.URL.Query()
		if query.Get("severity") != "critical" {
			t.Errorf("Expected severity=critical, got %s", query.Get("severity"))
		}
		if query.Get("fixable") != "true" {
			t.Errorf("Expected fixable=true, got %s", query.Get("fixable"))
		}
		if query.Get("exploitable") != "true" {
			t.Errorf("Expected exploitable=true, got %s", query.Get("exploitable"))
		}

		// Return mock response
		response := VulnerabilityResponse{
			Data: []Vulnerability{
				{
					ID:          "vuln-1",
					CVE:         "CVE-2023-0001",
					Severity:    "critical",
					Fixable:     true,
					Exploitable: true,
					Description: "Test vulnerability",
				},
			},
			Total: 1,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create client
	client := NewClient(server.URL, "test-token")

	// Create filter
	fixable := true
	exploitable := true
	filter := VulnerabilityFilter{
		Severity:    []string{"critical"},
		Fixable:     &fixable,
		Exploitable: &exploitable,
	}

	// Test
	vulns, err := client.ListVulnerabilitiesWithFilters(filter)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(vulns) != 1 {
		t.Fatalf("Expected 1 vulnerability, got %d", len(vulns))
	}

	vuln := vulns[0]
	if vuln.CVE != "CVE-2023-0001" {
		t.Errorf("Expected CVE-2023-0001, got %s", vuln.CVE)
	}
	if vuln.Severity != "critical" {
		t.Errorf("Expected severity critical, got %s", vuln.Severity)
	}
	if !vuln.Fixable {
		t.Error("Expected vulnerability to be fixable")
	}
	if !vuln.Exploitable {
		t.Error("Expected vulnerability to be exploitable")
	}
}

func TestListCriticalAndHighVulnerabilities(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return mock response with critical and high vulnerabilities
		response := VulnerabilityResponse{
			Data: []Vulnerability{
				{
					ID:          "vuln-1",
					CVE:         "CVE-2023-0001",
					Severity:    "critical",
					Fixable:     true,
					Exploitable: true,
				},
				{
					ID:          "vuln-2",
					CVE:         "CVE-2023-0002",
					Severity:    "high",
					Fixable:     true,
					Exploitable: true,
				},
			},
			Total: 2,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create client
	client := NewClient(server.URL, "test-token")

	// Test
	vulns, err := client.ListCriticalAndHighVulnerabilities()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(vulns) != 2 {
		t.Fatalf("Expected 2 vulnerabilities, got %d", len(vulns))
	}

	// Check first vulnerability
	if vulns[0].Severity != "critical" {
		t.Errorf("Expected first vulnerability to be critical, got %s", vulns[0].Severity)
	}

	// Check second vulnerability
	if vulns[1].Severity != "high" {
		t.Errorf("Expected second vulnerability to be high, got %s", vulns[1].Severity)
	}
}

func TestJoinParams(t *testing.T) {
	tests := []struct {
		name     string
		params   []string
		expected string
	}{
		{
			name:     "empty params",
			params:   []string{},
			expected: "",
		},
		{
			name:     "single param",
			params:   []string{"severity=critical"},
			expected: "severity=critical",
		},
		{
			name:     "multiple params",
			params:   []string{"severity=critical", "fixable=true", "exploitable=true"},
			expected: "severity=critical&fixable=true&exploitable=true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := joinParams(tt.params)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}