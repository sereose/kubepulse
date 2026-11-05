# kubepulse

Read-only Kubernetes audit in one binary. Points at your current kube-context, runs 15 checks across reliability, security, cost and hygiene, and prints a scored Markdown (or JSON) report in seconds.

```
$ kubepulse
# kubepulse audit report

**Score: 61/100 (grade C)** · 23 findings · generated 2026-11-04 10:12 UTC
...
## Top priorities

1. **[CRITICAL] Privileged containers** — `tools/Deployment/debug-box`: container "shell" runs privileged
2. **[HIGH] Containers without resource requests/limits** — `prod/Deployment/api`: container "api" is missing cpu request, memory request, memory limit
3. **[HIGH] Pods in CrashLoopBackOff, OOMKilled or stuck Pending** — `prod/Pod/worker-7f9c`: container "worker" was OOMKilled (14 restarts)
```

No agents, no CRDs, no write permissions. `list` on a handful of resource types is enough; anything RBAC denies is reported as a warning and skipped.

## Install

```bash
go install github.com/sereose/kubepulse/cmd/kubepulse@latest
```

or download a binary from Releases (`make release` builds linux/darwin, amd64/arm64).

## Usage

```bash
kubepulse                                  # audit current context, Markdown to stdout
kubepulse --context prod --output audit.md # pick a context, write to file
kubepulse --format json | jq '.score'      # machine-readable
kubepulse --namespace payments             # one namespace only
kubepulse --exclude-ns kube-system,istio-system,monitoring
```

### Offline audits (no cluster access for the reviewer)

```bash
# On a machine with cluster access — collects objects, strips managedFields:
kubepulse --save cluster.snapshot.json --output /dev/null

# Anywhere else:
kubepulse --load cluster.snapshot.json
```

The snapshot contains object specs and statuses (no Secrets, no ConfigMap data, no logs). Review it before sharing.

## Checks

| ID | Category | What it flags |
|---|---|---|
| WL001 | Reliability | Containers without CPU/memory requests or memory limit |
| WL002 | Reliability | Deployments/StatefulSets with `replicas: 1` |
| WL003 | Reliability | Containers without readiness/liveness probes |
| WL004 | Hygiene | Images on `:latest` or untagged |
| WL005 | Reliability | ≥2 replicas but no PodDisruptionBudget |
| SEC001 | Security | `privileged: true` containers |
| SEC002 | Security | Containers allowed to run as root |
| SEC003 | Security | `hostNetwork` / `hostPID` / `hostIPC` |
| NS001 | Hygiene | Active namespaces without ResourceQuota / LimitRange |
| POD001 | Reliability | CrashLoopBackOff, OOMKilled, stuck Pending, restart storms |
| COST001 | Cost | PVCs not mounted by any pod |
| COST002 | Cost | 3+ `LoadBalancer` services (one LB each) |
| COST003 | Cost/Reliability | Requests vs allocatable: oversized or no headroom |
| COST004 | Cost | ≥3 pinned replicas with no HPA |
| NODE001 | Reliability | Nodes NotReady or under memory/disk/PID pressure |

Score: 100 minus Critical=15, High=8, Medium=3, Low=1 per finding, with diminishing penalties after 40 points. Grades A ≥90, B ≥75, C ≥60, D ≥40.

## Adding a check

1. Implement the `checks.Check` interface in `internal/checks/` (see `workload_checks.go`).
2. Append it to `checks.Registry`.
3. Add a table-driven test building a `snapshot.Snapshot` by hand; no cluster needed.

Checks never call the API: everything they need is in the snapshot. That is deliberate — it keeps the tool fast, deterministic and testable, and makes the offline flow possible.

## Roadmap

- Usage vs requests via metrics-server / Prometheus (true right-sizing, with $ estimates per cloud)
- Ingress/Gateway TLS and cert expiry
- NetworkPolicy coverage per namespace
- Deprecated API versions ahead of upgrades
- Image CVE summary via Trivy integration
- HTML report and `--baseline` diff between runs
- Hosted version: scheduled audits, history, Slack digest

## Development

```bash
make test     # unit tests (no cluster needed)
make build    # ./bin/kubepulse
make lint
```

## License

MIT
