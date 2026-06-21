# Helm-chart `automountServiceAccountToken` survey

**Purpose.** Supporting evidence for the paper's claim (§6.3.1) that service-account
tokens are commonly left auto-mounted in real deployments, so the E2 credential-exfil
attack GCID detects is a live exposure rather than a hypothetical one.

**Method.** Convenience sample of 20 widely-used Helm charts. For each, we read the
**default `values.yaml`** on the project's default branch and recorded whether it sets
`automountServiceAccountToken: false`, sets it `true`, or leaves it unspecified (in which
case the Kubernetes default — `true` — applies). This is a directional sample of popular
charts, **not** a random or industry-wide statistic; chart defaults change over time, so
the finding should be read as of the access date.

**Access date:** 2026-06.

**Result: 16 of 20 charts mount the service-account token by default; only 4 disable it.**

| Disabled by default (`false`) — 4 | Token mounted by default (`true` or unspecified) — 16 |
|---|---|
| bitnami/nginx | kube-prometheus-stack, grafana¹, loki, ingress-nginx |
| bitnami/postgresql | elasticsearch, cert-manager, argo-cd, jaeger |
| bitnami/redis | external-dns, cilium, kyverno |
| bitnami/kafka | prometheus², vault², consul², metrics-server², fluent-bit² |

¹ grafana sets `false` at the ServiceAccount level but `true` at the Pod level; the
Pod-level setting wins, so the token is still mounted.
² unspecified in `values.yaml` → Kubernetes default (`true`) applies.

**Takeaway.** Outside the Bitnami chart family (which disables automounting by policy),
leaving the token mounted by default is the norm. Combined with the rarity of egress
NetworkPolicies (Bufalino et al. 2025: 241/287 ≈ 84% of applications lack any network
policy; Fairwinds 2024: only 37% of organizations have one), the two preventive controls
that would neutralize E2 are commonly absent — which is the deployment gap GCID addresses
as defense-in-depth.

**Reproduce.** Each chart's default `values.yaml` is public on its project repository
(e.g. `raw.githubusercontent.com/<org>/<repo>/<default-branch>/.../values.yaml`); grep for
`automountServiceAccountToken`.
