---
api_version: v1
http_method: GET
category: vulnerability-management
implemented: true
implemented_in: pkg/sysdig/client.go:384-459
requires_auth: true
rate_limit: unknown
pagination_type: cursor
related_endpoints:
  - /secure/vulnerability/v1/runtime-results
  - /secure/vulnerability/v1/results/{resultId}
notes: |
  - cursor paginationを使用
  - createdAtフィールドでクライアント側の日数フィルタリングが可能
  - デフォルトlimit=100、maxPages=200で実装
  - freeTextパラメータでイメージ名の部分一致検索が可能
---

# endpoint
https://api.us2.sysdig.com/secure/vulnerability/v1/pipeline-results

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
Example: filter=freeText in ("nginx")
Query language expression for filtering results. It is a subset of the full metrics query language used in monitoring.

Only the freeText parameter is supported:

freeText as string value (note that it will search on the full image name)

# response example
```
{
  "data": [
    {
      "createdAt": "2024-01-22T08:51:46.016464Z",
      "imageId": "sha256:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6",
      "policyEvaluationResult": "passed",
      "pullString": "nginx:latest",
      "resultId": "scan-1234",
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
