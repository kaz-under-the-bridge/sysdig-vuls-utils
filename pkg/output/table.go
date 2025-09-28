package output

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/kaz-under-the-bridge/sysdig-vuls-utils/pkg/sysdig"
)

// TableWriter handles table output for vulnerabilities
type TableWriter struct {
	writer io.Writer
}

// NewTableWriter creates a new table writer
func NewTableWriter(writer io.Writer) *TableWriter {
	if writer == nil {
		writer = os.Stdout
	}
	return &TableWriter{writer: writer}
}

// WriteVulnerabilities writes vulnerabilities in table format
func (tw *TableWriter) WriteVulnerabilities(vulnerabilities []sysdig.Vulnerability) error {
	if len(vulnerabilities) == 0 {
		fmt.Fprintln(tw.writer, "No vulnerabilities found.")
		return nil
	}

	// Create tabwriter
	w := tabwriter.NewWriter(tw.writer, 0, 0, 2, ' ', 0)
	defer w.Flush()

	// Write header
	fmt.Fprintln(w, "ID\tCVE\tSeverity\tScore\tFixable\tExploitable\tPackages\tStatus")
	fmt.Fprintln(w, strings.Repeat("-", 100))

	// Write data
	for _, vuln := range vulnerabilities {
		packages := strings.Join(vuln.Packages, ", ")
		if len(packages) > 30 {
			packages = packages[:27] + "..."
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%.1f\t%t\t%t\t%s\t%s\n",
			truncate(vuln.ID, 15),
			truncate(vuln.CVE, 15),
			vuln.Severity,
			vuln.Score,
			vuln.Fixable,
			vuln.Exploitable,
			packages,
			vuln.Status,
		)
	}

	return nil
}

// WriteDetailedVulnerabilities writes detailed vulnerability information
func (tw *TableWriter) WriteDetailedVulnerabilities(vulnerabilities []sysdig.Vulnerability) error {
	if len(vulnerabilities) == 0 {
		fmt.Fprintln(tw.writer, "No vulnerabilities found.")
		return nil
	}

	// Create tabwriter
	w := tabwriter.NewWriter(tw.writer, 0, 0, 2, ' ', 0)
	defer w.Flush()

	// Write header
	fmt.Fprintln(w, "CVE\tSeverity\tScore\tFixable\tExploitable\tFixed Version\tAWS Accounts\tResource Types\tContainer Image")
	fmt.Fprintln(w, strings.Repeat("-", 150))

	// Write data
	for _, vuln := range vulnerabilities {
		// Collect AWS accounts
		accountMap := make(map[string]bool)
		resourceTypeMap := make(map[string]bool)
		for _, res := range vuln.AWSResources {
			if res.AccountID != "" {
				accountMap[res.AccountID] = true
			}
			if res.ResourceType != "" {
				resourceTypeMap[res.ResourceType] = true
			}
		}

		accounts := []string{}
		for acc := range accountMap {
			accounts = append(accounts, acc)
		}
		resourceTypes := []string{}
		for rt := range resourceTypeMap {
			resourceTypes = append(resourceTypes, rt)
		}

		// Get container image info
		containerImage := "-"
		if vuln.ContainerInfo != nil {
			containerImage = fmt.Sprintf("%s:%s", vuln.ContainerInfo.ImageName, vuln.ContainerInfo.ImageTag)
		}

		fmt.Fprintf(w, "%s\t%s\t%.1f\t%t\t%t\t%s\t%s\t%s\t%s\n",
			truncate(vuln.CVE, 20),
			vuln.Severity,
			vuln.Score,
			vuln.Fixable,
			vuln.Exploitable,
			truncate(vuln.FixedVersion, 20),
			truncate(strings.Join(accounts, ","), 30),
			truncate(strings.Join(resourceTypes, ","), 20),
			truncate(containerImage, 40),
		)
	}

	return nil
}

// WriteSummary writes a summary of vulnerabilities
func (tw *TableWriter) WriteSummary(vulnerabilities []sysdig.Vulnerability) error {
	// Count by severity
	severityCount := make(map[string]int)
	fixableCount := 0
	exploitableCount := 0
	criticalFixable := 0
	highFixable := 0

	for _, vuln := range vulnerabilities {
		severityCount[vuln.Severity]++
		if vuln.Fixable {
			fixableCount++
			if vuln.Severity == "critical" {
				criticalFixable++
			} else if vuln.Severity == "high" {
				highFixable++
			}
		}
		if vuln.Exploitable {
			exploitableCount++
		}
	}

	// Count by AWS resource type
	resourceCount := make(map[string]int)
	for _, vuln := range vulnerabilities {
		for _, res := range vuln.AWSResources {
			if res.ResourceType != "" {
				resourceCount[res.ResourceType]++
			}
		}
	}

	// Count by detection source
	sourceCount := make(map[string]int)
	for _, vuln := range vulnerabilities {
		for _, src := range vuln.DetectionSources {
			if src.Type != "" {
				sourceCount[src.Type]++
			}
		}
	}

	// Print summary
	fmt.Fprintln(tw.writer, "\n=== Vulnerability Summary ===")
	fmt.Fprintf(tw.writer, "Total Vulnerabilities: %d\n", len(vulnerabilities))
	fmt.Fprintln(tw.writer, "\n--- By Severity ---")
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if count, ok := severityCount[sev]; ok {
			fmt.Fprintf(tw.writer, "  %-10s: %d\n", strings.Title(sev), count)
		}
	}

	fmt.Fprintln(tw.writer, "\n--- Actionable Items ---")
	fmt.Fprintf(tw.writer, "  Fixable vulnerabilities     : %d\n", fixableCount)
	fmt.Fprintf(tw.writer, "  Critical (fixable)          : %d\n", criticalFixable)
	fmt.Fprintf(tw.writer, "  High (fixable)              : %d\n", highFixable)
	fmt.Fprintf(tw.writer, "  Exploitable vulnerabilities : %d\n", exploitableCount)

	if len(resourceCount) > 0 {
		fmt.Fprintln(tw.writer, "\n--- By AWS Resource Type ---")
		for resType, count := range resourceCount {
			fmt.Fprintf(tw.writer, "  %-10s: %d\n", resType, count)
		}
	}

	if len(sourceCount) > 0 {
		fmt.Fprintln(tw.writer, "\n--- By Detection Source ---")
		for srcType, count := range sourceCount {
			fmt.Fprintf(tw.writer, "  %-10s: %d\n", srcType, count)
		}
	}

	return nil
}

// WriteAWSResourceTable writes AWS resource information in table format
func (tw *TableWriter) WriteAWSResourceTable(vulnerabilities []sysdig.Vulnerability) error {
	// Collect all AWS resources with vulnerability info
	type resourceVuln struct {
		resource sysdig.AWSResource
		vuln     sysdig.Vulnerability
	}

	resources := []resourceVuln{}
	for _, vuln := range vulnerabilities {
		for _, res := range vuln.AWSResources {
			resources = append(resources, resourceVuln{
				resource: res,
				vuln:     vuln,
			})
		}
	}

	if len(resources) == 0 {
		fmt.Fprintln(tw.writer, "No AWS resources found with vulnerabilities.")
		return nil
	}

	// Create tabwriter
	w := tabwriter.NewWriter(tw.writer, 0, 0, 2, ' ', 0)
	defer w.Flush()

	// Write header
	fmt.Fprintln(w, "Account ID\tResource Type\tResource ID\tRegion\tCVE\tSeverity\tFixable")
	fmt.Fprintln(w, strings.Repeat("-", 120))

	// Write data
	for _, rv := range resources {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%t\n",
			rv.resource.AccountID,
			rv.resource.ResourceType,
			truncate(rv.resource.ResourceID, 30),
			rv.resource.Region,
			rv.vuln.CVE,
			rv.vuln.Severity,
			rv.vuln.Fixable,
		)
	}

	return nil
}

// truncate truncates a string to the specified length
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}