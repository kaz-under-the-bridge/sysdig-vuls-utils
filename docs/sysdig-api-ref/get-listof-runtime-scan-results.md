---
api_version: v1
http_method: GET
category: vulnerability-management
implemented: true
implemented_in: pkg/sysdig/client.go:462-673
requires_auth: true
rate_limit: unknown
pagination_type: cursor
related_endpoints:
  - /secure/vulnerability/v1/pipeline-results
  - /secure/vulnerability/v1/results/{resultId}
notes: |
  - cursor paginationを使用
  - createdAtフィールドが存在しないため期間フィルタリング不可
  - asset.type別のフィルタリングをサポート（workload/host/container）
  - デフォルトlimit=100、maxPages=50で実装
  - workloadはデフォルト300件制限、host/containerは無制限
  - filterパラメータでKubernetesメタデータによる絞り込みが可能
  - hasRunningVulns, hasRunningVulnsフィールドでランタイム脆弱性フィルタリング可能
---

# endpoint
https://api.us2.sysdig.com/secure/vulnerability/v1/runtime-results

# query Parameters
cursor	
string <= 300 characters
Example: cursor=MTI0MjM0Cg==
Cursor is a string used to retrieve a particular page of data. It is an opaque structure, and should not be mangled. It could be retrieved in the body of each request. If a response does not contain a cursor, it means that it's the last page.

limit	
integer <int64> [ 1 .. 1000 ]
Default: 1000
Limit for pagination

filter	
string <= 1024 characters
Example: filter=kubernetes.cluster.name="staging" and kubernetes.pod.container.name="docker.internal.sysdig.tools"
Query language expression for filtering results. It is a subset of the full metrics query language used in monitoring.

Operators:

and, or logical operators (i.e. kubernetes.cluster.name="production" and kubernetes.pod.container.name = "docker.internal.sysdig.tools")

= and != comparison operators (i.e. kubernetes.cluster.name="staging")

This query language does not support the full set of metrics supported in the monitor query language, but instead supports a set of fields proper to each Scan Result type.

The supported fields are the all the fields of the Scope, plus: freeText, hasRunningVulns and hasRunningVulns.

sort	
string
Default: "vulnTotalBySeverity"
Enum: "vulnTotalBySeverity" "runningVulnTotalBySeverity"
Example: sort=runningVulnTotalBySeverity
Field used to sort the results vulnTotalBySeverity: sort by total number of running vulnerabilities weighted by severity runningVulnTotalBySeverity: sort by total number of running vulnerabilities weighted by severity for running assets

order	
string
Default: "desc"
Enum: "desc" "asc"
Example: order=asc
Ordering of the results for the sort field

# response sample
```
{
  "data": [
    {
      "isRiskSpotlightEnabled": true,
      "mainAssetName": "nginx:latest",
      "policyEvaluationResult": "passed",
      "resourceId": "sha256:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6",
      "resultId": "scan-1234",
      "runningVulnTotalBySeverity": {
        "critical": 12345,
        "high": 12345,
        "low": 12345,
        "medium": 12345,
        "negligible": 12345
      },
      "sbomId": "sbom-1234",
      "scope": {
        "asset.type": "workload",
        "kubernetes.cluster.name": "prod-cluster-00",
        "kubernetes.namespace.name": "foo",
        "kubernetes.workload.name": "bar",
        "kubernetes.workload.type": "deployment"
      },
      "vulnTotalBySeverity": {
        "critical": 12345,
        "high": 12345,
        "low": 12345,
        "medium": 12345,
        "negligible": 12345
      }
    }
  ],
  "page": {
    "next": "MTI0MjM0Cg==",
    "total": 1
  }
}
```
