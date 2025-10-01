package output

import (
	"fmt"
	"io"

	"github.com/kaz-under-the-bridge/sysdig-vuls-utils/pkg/sysdig"
)

// TableWriter writes vulnerability data in table format
type TableWriter struct {
	writer io.Writer
}

// NewTableWriter creates a new TableWriter
func NewTableWriter(writer io.Writer) *TableWriter {
	return &TableWriter{writer: writer}
}

// WriteVulnerabilities writes vulnerability information - simplified for V2 API
func (tw *TableWriter) WriteVulnerabilities(vulnerabilities []sysdig.Vulnerability) error {
	if len(vulnerabilities) == 0 {
		fmt.Fprintln(tw.writer, "No vulnerabilities found.")
		return nil
	}

	fmt.Fprintf(tw.writer, "Found %d vulnerabilities\n", len(vulnerabilities))
	for i, vuln := range vulnerabilities {
		fixedVersion := "none"
		if vuln.FixedInVersion != nil {
			fixedVersion = *vuln.FixedInVersion
		}
		fmt.Fprintf(tw.writer, "%d. %s [%s] - %s (Fixable: %t, Fixed in: %s)\n",
			i+1, vuln.Vuln.Name, vuln.Vuln.SeverityString(),
			vuln.Package.Name, vuln.Vuln.Fixable, fixedVersion)
	}

	return nil
}

// WriteDetailedVulnerabilities writes detailed vulnerability information
func (tw *TableWriter) WriteDetailedVulnerabilities(vulnerabilities []sysdig.Vulnerability) error {
	return tw.WriteVulnerabilities(vulnerabilities)
}

// WriteSummary writes a summary of vulnerabilities
func (tw *TableWriter) WriteSummary(vulnerabilities []sysdig.Vulnerability) error {
	severityCount := make(map[string]int)
	fixableCount := 0

	for _, vuln := range vulnerabilities {
		severityCount[vuln.Vuln.SeverityString()]++
		if vuln.Vuln.Fixable {
			fixableCount++
		}
	}

	fmt.Fprintf(tw.writer, "Vulnerability Summary:\n")
	fmt.Fprintf(tw.writer, "Total: %d\n", len(vulnerabilities))
	fmt.Fprintf(tw.writer, "Fixable: %d\n", fixableCount)
	fmt.Fprintf(tw.writer, "By Severity:\n")
	for severity, count := range severityCount {
		fmt.Fprintf(tw.writer, "  %s: %d\n", severity, count)
	}

	return nil
}

// WriteAWSResourceTable writes AWS resources with vulnerabilities - not available in V2 API
func (tw *TableWriter) WriteAWSResourceTable(vulnerabilities []sysdig.Vulnerability) error {
	fmt.Fprintln(tw.writer, "AWS Resource view not available in V2 API")
	return tw.WriteVulnerabilities(vulnerabilities)
}
