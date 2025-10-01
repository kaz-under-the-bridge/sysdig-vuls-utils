// Package testutil provides test fixtures and utilities for testing Sysdig API client.
package testutil

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

//go:embed fixtures/pipeline_page1.json
var pipelinePage1JSON string

//go:embed fixtures/pipeline_page2.json
var pipelinePage2JSON string

//go:embed fixtures/runtime_page1.json
var runtimePage1JSON string

//go:embed fixtures/runtime_page2.json
var runtimePage2JSON string

//go:embed fixtures/vulnerabilities.json
var vulnerabilitiesJSON string

// replacePlaceholders は、JSONテンプレート内のプレースホルダーを実際の値に置換する
func replacePlaceholders(jsonStr string) string {
	now := time.Now()

	// {{RECENT_TIME_3D}} → 3日前のタイムスタンプ
	recent3d := now.AddDate(0, 0, -3).Format(time.RFC3339)
	jsonStr = strings.ReplaceAll(jsonStr, "{{RECENT_TIME_3D}}", recent3d)

	// {{RECENT_TIME_2D}} → 2日前のタイムスタンプ
	recent2d := now.AddDate(0, 0, -2).Format(time.RFC3339)
	jsonStr = strings.ReplaceAll(jsonStr, "{{RECENT_TIME_2D}}", recent2d)

	return jsonStr
}

// PipelineResultsPage1 returns the first page of pipeline results
func PipelineResultsPage1() string {
	return replacePlaceholders(pipelinePage1JSON)
}

// PipelineResultsPage2 returns the second page (last page) of pipeline results
func PipelineResultsPage2() string {
	return replacePlaceholders(pipelinePage2JSON)
}

// RuntimeResultsPage1 returns the first page of runtime results
func RuntimeResultsPage1() string {
	return replacePlaceholders(runtimePage1JSON)
}

// RuntimeResultsPage2 returns the second page (last page) of runtime results
func RuntimeResultsPage2() string {
	return replacePlaceholders(runtimePage2JSON)
}

// VulnerabilitiesFixture returns vulnerabilities and packages data
func VulnerabilitiesFixture() string {
	return vulnerabilitiesJSON
}

// FullScanResultFixture returns a complete scan result with embedded vulnerabilities
func FullScanResultFixture() string {
	// vulnerabilities.jsonから脆弱性データを読み込み、FullScanResult形式に変換
	var vulnData struct {
		Vulnerabilities map[string]interface{} `json:"vulnerabilities"`
		Packages        map[string]interface{} `json:"packages"`
	}

	if err := json.Unmarshal([]byte(vulnerabilitiesJSON), &vulnData); err != nil {
		return "{}"
	}

	result := map[string]interface{}{
		"assetType": "containerImage",
		"stage":     "pipeline",
		"metadata": map[string]interface{}{
			"pullString": "123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/demo-frontend:abc123def456",
			"imageId":    "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		},
		"vulnerabilities": vulnData.Vulnerabilities,
		"packages":        vulnData.Packages,
		"policies": map[string]interface{}{
			"globalEvaluation": "failed",
		},
		"producer": map[string]interface{}{
			"producedAt": time.Now().AddDate(0, 0, -1).Format(time.RFC3339),
		},
		"riskAccepts": map[string]interface{}{},
	}

	jsonBytes, _ := json.MarshalIndent(result, "", "  ")
	return string(jsonBytes)
}

// GetVulnerabilitySummary は脆弱性データのサマリーを返す（テスト用）
func GetVulnerabilitySummary() map[string]interface{} {
	var vulnData struct {
		Vulnerabilities map[string]interface{} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal([]byte(vulnerabilitiesJSON), &vulnData); err != nil {
		return nil
	}

	summary := map[string]interface{}{
		"total": len(vulnData.Vulnerabilities),
		"combinations": map[string]int{
			"exploitable_fixable":         0,
			"exploitable_not_fixable":     0,
			"not_exploitable_fixable":     0,
			"not_exploitable_not_fixable": 0,
		},
	}

	for _, vuln := range vulnData.Vulnerabilities {
		v := vuln.(map[string]interface{})
		exploitable := v["exploitable"].(bool)
		fixVersion := v["fixVersion"].(string)
		fixable := fixVersion != ""

		key := ""
		if exploitable && fixable {
			key = "exploitable_fixable"
		} else if exploitable && !fixable {
			key = "exploitable_not_fixable"
		} else if !exploitable && fixable {
			key = "not_exploitable_fixable"
		} else {
			key = "not_exploitable_not_fixable"
		}

		summary["combinations"].(map[string]int)[key]++
	}

	return summary
}

// ValidateFixtureJSON は、JSONフィクスチャの妥当性をチェックする（テスト用）
func ValidateFixtureJSON(jsonStr string) error {
	var data interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}
