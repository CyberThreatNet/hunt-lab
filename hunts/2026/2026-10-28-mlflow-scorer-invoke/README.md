# MLflow scorer invoke (CVE-2026-116692)

> **Draft: untested.** Path-based hunt for the scorer invoke API named in the CVE.

| | |
|---|---|
| **Hunt ID** | `2026-10-28-mlflow-scorer-invoke` |
| **Date** | 28 October 2026 |
| **Status** | Draft: untested |
| **CVEs** | CVE-2026-116692 — [`cve-context.yaml`](cve-context.yaml) |

## Hypothesis

Abuse of the weak third-party scorer allow-list shows up as HTTP calls to `/ajax-api/3.0/mlflow/scorer/invoke`, often with preceding artifact uploads. Tune heavily on estates that use GenAI scorers legitimately. Upgrade tracking servers to 3.17.0+.
