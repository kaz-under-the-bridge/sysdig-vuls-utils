---
api_version: v1
http_method: GET
category: vulnerability-management
implemented: true
implemented_in: pkg/sysdig/client.go:825-926
requires_auth: true
rate_limit: unknown
pagination_type: none
related_endpoints:
  - /secure/vulnerability/v1/pipeline-results
  - /secure/vulnerability/v1/runtime-results
notes: |
  - 完全なスキャン結果（metadata, packages, vulnerabilities, policies, layers等）を返す
  - GetFullScanResult()メソッドで完全なスキャン結果を取得
  - GetScanResultVulnerabilities()メソッドでpackagesとvulnerabilitiesの参照関係を辿り脆弱性リストを構築
  - SBOM、ポリシー評価、レイヤー情報、リスク受容情報等を含む
  - 非公式のV2 vulnPkgs APIは非推奨となり、このV1 APIを使用するように変更
---

# endpoint
https://api.us2.sysdig.com/secure/vulnerability/v1/results/{resultId}

# path Parameters
resultId
required
string <= 255 characters
Example: 176c77d16ee6bdd2f7482d4ec0fd0542
The ID of a single scan result. Could be retrieved by one of the listing endpoints.

# response sample
```
{
  "assetType": "containerImage",
  "baseImages": {
    "a3ee5e6b4b0d3255bf": {
      "pullStrings": [
        "alpine:latest"
      ]
    }
  },
  "layers": {
    "f95aa9ae66563e7e808b": {
      "baseImagesRef": [
        "a3ee5e6b4b0d3255bf"
      ],
      "command": "COPY docker-entrypoint.sh",
      "digest": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "size": 50
    }
  },
  "metadata": {
    "architecture": "arm64",
    "author": "sysdig",
    "baseOs": "debian",
    "createdAt": "2024-01-22T08:51:46.016464Z",
    "digest": "sha256:77af4d6b9913e693e8d0b4b294fa62ade6054e6b2f1ffb617ac955dd63fb0182",
    "imageId": "sha256:77af4d6b9913e693e8d0b4b294fa62ade6054e6b2f1ffb617ac955dd63fb0182",
    "labels": {
      "key": "value"
    },
    "os": "debian",
    "pullString": "nginx:latest",
    "size": 10240
  },
  "packages": {
    "2772f8a6c73fa17": {
      "isRemoved": true,
      "isRunning": true,
      "layerRef": "f95aa9ae66563e7e808b",
      "license": "MIT",
      "name": "openssl",
      "path": "/usr/local/bin/openssl",
      "riskAcceptRefs": [
        "acb4b0d2565bfef"
      ],
      "suggestedFix": "1.2.3",
      "type": "os",
      "version": "1.2.3",
      "vulnerabilitiesRefs": [
        "71af37c6a8f2772"
      ]
    }
  },
  "policies": {
    "evaluations": [
      {
        "bundles": [
          {
            "identifier": "severe_vulnerabilities_with_a_fix",
            "name": "Severe vulnerabilities with a Fix",
            "rules": [
              {
                "description": "rule description",
                "evaluationResult": "passed",
                "failureType": "pkgVulnFailure",
                "failures": [
                  {
                    "arguments": {},
                    "riskAcceptRefs": []
                  }
                ],
                "predicates": [
                  {
                    "extra": {}
                  }
                ],
                "ruleId": "1234A",
                "ruleType": "vulnDenyList"
              }
            ],
            "type": "predefined"
          }
        ],
        "createdAt": "2024-01-22T08:51:46.016464Z",
        "description": "description",
        "evaluation": "passed",
        "identifier": "550e8400-e29b",
        "name": "policy-0",
        "updatedAt": "2024-01-22T08:51:46.016464Z"
      }
    ],
    "globalEvaluation": "passed"
  },
  "producer": {
    "producedAt": "2024-01-22T08:51:46Z"
  },
  "riskAccepts": {
    "e6b4b0d3255bfef": {
      "context": [
        {
          "type": "imageName",
          "value": "nginx:latest"
        }
      ],
      "createdAt": "2024-01-22T08:51:46.016464Z",
      "description": "description",
      "entityType": "imageName",
      "entityValue": "nginx:latest",
      "expirationDate": "2021-07-01",
      "id": "550e8400-e29b",
      "reason": "RiskMitigated",
      "status": "active",
      "updatedAt": "2024-01-22T08:51:46.016464Z"
    }
  },
  "stage": "pipeline",
  "vulnerabilities": {
    "71af37c6a8f2772": {
      "cisaKev": {
        "dueDate": "2023-10-31",
        "knownRansomwareCampaignUse": false,
        "publishDate": "2023-12-06"
      },
      "cvssScore": {
        "score": 1,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "version": "3.0"
      },
      "disclosureDate": "2021-01-02",
      "exploit": {
        "links": [
          "https://sysdig.com/exploits/12345"
        ],
        "publicationDate": "2024-01-22T08:51:46.00Z"
      },
      "exploitable": true,
      "fixVersion": "1.2.3",
      "mainProvider": "vulndb",
      "name": "CVE-2021-1234",
      "packageRef": "2772f8a6c73fa17",
      "providersMetadata": {
        "nvd": {}
      },
      "riskAcceptRefs": [
        "e6b4b0d3255bfef"
      ],
      "severity": "high",
      "solutionDate": "2021-01-02"
    }
  }
}
```
