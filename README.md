# kubepulse

Read-only Kubernetes audit in one binary. Points at your current kube-context, runs 24 checks across reliability, security, cost and hygiene, and prints a scored Markdown (or JSON) report in seconds.

```
$ kubepulse --node-monthly-cost 150 --storage-cost-per-gi 0.10
# kubepulse audit report

**Score: 61/100 (grade C)** · 23 findings · generated 2026-11-05 10:12 UTC
...
## Top priorities

1. **[CRITICAL] Privileged containers** — `tools/Deployment/debug-box`: container "shell" runs privileged
2. **[HIGH] Containers recently OOMKilled** — `prod/Pod/api-6d9f-abc`: container "api" was OOMKilled (14 restarts)
3. **[HIGH] Ingress hosts without TLS** — `prod/Ingress/web`: no TLS section for host(s): app.example.com
...
| MEDIUM | — | `cluster` | requests use 18% of allocatable CPU ... — the cluster is likely oversized; ~$370/month of node capacity is unrequested |
```

No agents, no CRDs, no write permissions. `list` on a handful of resource types is enough; anything RBAC denies is reported as a warning and skipped.

## Install

```bash
go install github.com/sereose/kubepulse/cmd/kubepulse@latest
```

Or download a binary for linux/darwin/windows (amd64/arm64) from [Releases](https://github.com/sereose/kubepulse/releases).

## Usage

```bash
kubepulse                                   # audit current context, Markdown to stdout
kubepulse --context prod --output audit.md  # pick a context, write to file
kubepulse --format json | jq '.score'       # machine-readable
kubepulse --namespace payments              # one namespace only
kubepulse --exclude-ns kube-system,istio-system,monitoring
```

### Put a price on it

Cost findings stay relative ("18% of capacity requested") until you tell kubepulse what a node and a Gi of storage cost you:

```bash
kubepulse --node-monthly-cost 150 --storage-cost-per-gi 0.10
```

Both are averages you read off your cloud bill; the estimates are deliberately rough and say so.

### CI gate

```bash
kubepulse --fail-below 70   # exit code 2 if score < 70
```

Run it in a nightly job or after every deploy to catch regressions (a new privileged pod, a dropped probe) before someone else does.

### Offline audits (no cluster access for the reviewer)

```bash
# On a machine with cluster access — collects objects, strips managedFields and container env:
kubepulse --save cluster.snapshot.json --output /dev/null

# Anywhere else:
kubepulse --load cluster.snapshot.json
```

The snapshot holds object specs and statuses only: no Secrets, no ConfigMap data, no logs, and container `env` is removed. Review it before sharing.

### Try it on a throwaway cluster

```bash
kind create cluster --name kubepulse-demo
kubectl apply -f https://raw.githubusercontent.com/sereose/kubepulse/main/testdata/demo-workloads.yaml
kubepulse --context kind-kubepulse-demo
```

## Checks

| ID | Category | Severity | What it flags |
|---|---|---|---|
| WL001 | Reliability | High/Medium | Containers without CPU/memory requests or memory limit |
| WL002 | Reliability | Medium | Deployments/StatefulSets with `replicas: 1` |
| WL003 | Reliability | Medium | Containers without readiness/liveness probes |
| WL004 | Hygiene | Medium | Images on `:latest` or untagged |
| WL005 | Reliability | Medium | ≥2 replicas but no PodDisruptionBudget |
| WL006 | Reliability | Medium | ≥2 replicas, no anti-affinity / topology spread (multi-node clusters) |
| SEC001 | Security | Critical | `privileged: true` containers |
| SEC002 | Security | High | Containers allowed to run as root |
| SEC003 | Security | High | `hostNetwork` / `hostPID` / `hostIPC` (Medium for DaemonSets) |
| SEC004 | Security | Medium | Default ServiceAccount with API token auto-mounted |
| SEC005 | Security | High | Ingress hosts without TLS |
| SEC006 | Security | Low | Missing `allowPrivilegeEscalation: false`, read-only rootfs, `drop: [ALL]` |
| NS001 | Hygiene | Low | Active namespaces without ResourceQuota / LimitRange |
| NS002 | Security | Medium | Active namespaces without any NetworkPolicy |
| POD001 | Reliability | High | Pods stuck in Pending (default > 10 min) |
| POD002 | Reliability | High | Containers in CrashLoopBackOff |
| POD003 | Reliability | High | Containers recently OOMKilled |
| POD004 | Reliability | Medium | Running containers with ≥10 restarts |
| COST001 | Cost | Medium | PVCs not mounted by any pod (+ priced total) |
| COST002 | Cost | Medium | 3+ `LoadBalancer` services (one cloud LB each) |
| COST003 | Cost/Reliability | Medium/High | Requests vs allocatable: oversized (+ $ idle) or no headroom |
| COST004 | Cost | Low | ≥3 pinned replicas with no HPA |
| NODE001 | Reliability | Critical/High | Nodes NotReady or under memory/disk/PID pressure |

Score: 100 minus Critical=15, High=8, Medium=3, Low=1 per finding, with diminishing penalties after 40 points. Grades A ≥90, B ≥75, C ≥60, D ≥40.

Findings are heuristics. A `hostNetwork` DaemonSet is usually a CNI agent; a single-replica Deployment may be a cron-like worker. The report tells you what to look at, not what to do blindly.

## Adding a check

1. Implement the `checks.Check` interface in `internal/checks/` (see `workload_checks.go`).
2. Append it to `checks.Registry`.
3. Add a test that builds a `snapshot.Snapshot` by hand; no cluster needed.

Checks never call the API: everything they need is in the snapshot. That keeps the tool fast, deterministic and testable, and makes the offline flow possible.

## Roadmap

- Usage vs requests via metrics-server / Prometheus (true right-sizing per workload)
- Deprecated API versions ahead of upgrades
- Cert expiry for Ingress TLS secrets
- Image CVE summary via Trivy
- `--baseline` diff between two runs; HTML report
- Hosted version: scheduled audits, history, Slack digest

## Development

```bash
make test     # unit tests, no cluster needed
make build    # ./bin/kubepulse
make lint
./bin/kubepulse --load testdata/fixture.json   # end-to-end on a deliberately bad snapshot
```

Releases: push a tag `vX.Y.Z`; GitHub Actions runs goreleaser and publishes binaries.

## License

MIT
