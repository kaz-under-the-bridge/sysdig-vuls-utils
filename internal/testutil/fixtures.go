// Package testutil provides test fixtures and utilities for testing Sysdig API client.
package testutil

import (
	"time"
)

// PipelineResultsFixture returns a sample pipeline results response matching API ref spec
// This function now loads data from fixtures/pipeline_page1.json
func PipelineResultsFixture() string {
	return PipelineResultsPage1()
}

// PipelineResultsLastPageFixture returns the last page (no cursor)
// This function now loads data from fixtures/pipeline_page2.json
func PipelineResultsLastPageFixture() string {
	return PipelineResultsPage2()
}

// RuntimeResultsFixture returns a sample runtime results response matching API ref spec
// This function now loads data from fixtures/runtime_page1.json
func RuntimeResultsFixture() string {
	return RuntimeResultsPage1()
}

// RuntimeResultsLastPageFixture returns the last page (no cursor)
// This function now loads data from fixtures/runtime_page2.json
func RuntimeResultsLastPageFixture() string {
	return RuntimeResultsPage2()
}

// FullScanResultNotFoundFixture returns a 404 error response
func FullScanResultNotFoundFixture() string {
	return `{"message": "scan result not found"}`
}

// AcceptedRisksFixture returns a sample accepted risks response
func AcceptedRisksFixture() string {
	return `{
  "data": [
    {
      "context": [
        {
          "type": "imageName",
          "value": "nginx:latest"
        }
      ],
      "createdAt": "2024-01-15T10:30:00.000000Z",
      "description": "Risk mitigated by network segmentation",
      "entityType": "vulnerability",
      "entityValue": "CVE-2023-0286",
      "expirationDate": "2024-07-01",
      "id": "risk-accept-1234",
      "reason": "RiskMitigated",
      "status": "active",
      "updatedAt": "2024-01-15T10:30:00.000000Z"
    }
  ],
  "page": {
    "next": "Umlza0FjY2VwdFBhZ2Uy",
    "total": 1
  }
}`
}

// AcceptedRisksLastPageFixture returns the last page (no cursor)
func AcceptedRisksLastPageFixture() string {
	return `{
  "data": [
    {
      "context": [
        {
          "type": "imageName",
          "value": "alpine:3.18"
        }
      ],
      "createdAt": "2024-01-20T14:00:00.000000Z",
      "description": "Temporary acceptance pending vendor fix",
      "entityType": "vulnerability",
      "entityValue": "CVE-2023-0465",
      "expirationDate": "2024-06-30",
      "id": "risk-accept-5678",
      "reason": "VendorFixPending",
      "status": "active",
      "updatedAt": "2024-01-20T14:00:00.000000Z"
    }
  ],
  "page": {
    "total": 1
  }
}`
}

// GetOldResultCreatedAt returns a timestamp older than the specified days
func GetOldResultCreatedAt(days int) string {
	oldTime := time.Now().AddDate(0, 0, -(days + 1))
	return oldTime.Format(time.RFC3339Nano)
}

// GetRecentResultCreatedAt returns a timestamp within the specified days
func GetRecentResultCreatedAt(days int) string {
	recentTime := time.Now().AddDate(0, 0, -(days - 1))
	return recentTime.Format(time.RFC3339Nano)
}
