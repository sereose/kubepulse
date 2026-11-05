package checks

import (
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/sereose/kubepulse/internal/snapshot"
)

// ---- namespace guardrails --------------------------------------------------

type namespaceGuardrails struct{}

func (namespaceGuardrails) ID() string    { return "NS001" }
func (namespaceGuardrails) Title() string { return "Namespaces without ResourceQuota or LimitRange" }

func (c namespaceGuardrails) Run(s *snapshot.Snapshot, o Options) []Finding {
	hasQuota := map[string]bool{}
	for _, q := range s.ResourceQuotas {
		hasQuota[q.Namespace] = true
	}
	hasLR := map[string]bool{}
	for _, l := range s.LimitRanges {
		hasLR[l.Namespace] = true
	}
	// Only flag namespaces that actually run workloads.
	active := map[string]bool{}
	for _, p := range s.Pods {
		active[p.Namespace] = true
	}
	var out []Finding
	for _, ns := range s.Namespaces {
		if o.excluded(ns.Name) || !active[ns.Name] || ns.Name == "default" && !active["default"] {
			continue
		}
		var missing []string
		if !hasQuota[ns.Name] {
			missing = append(missing, "ResourceQuota")
		}
		if !hasLR[ns.Name] {
			missing = append(missing, "LimitRange")
		}
		if len(missing) == 0 {
			continue
		}
		out = append(out, Finding{
			CheckID: c.ID(), Title: c.Title(), Severity: Low, Category: Hygiene,
			Namespace: ns.Name, Object: "Namespace/" + ns.Name,
			Message:     "no " + strings.Join(missing, " or "),
			Remediation: "Add a LimitRange with default requests/limits so forgotten resource specs get sane values, and a ResourceQuota to cap what one team can consume.",
		})
	}
	return out
}

// ---- unhealthy pods --------------------------------------------------------

type unhealthyPods struct{}

func (unhealthyPods) ID() string    { return "POD001" }
func (unhealthyPods) Title() string { return "Pods in CrashLoopBackOff, OOMKilled or stuck Pending" }

func (c unhealthyPods) Run(s *snapshot.Snapshot, o Options) []Finding {
	var out []Finding
	threshold := time.Duration(o.PendingThresholdSeconds) * time.Second
	now := s.CollectedAt
	if now.IsZero() {
		now = time.Now()
	}
	for _, p := range s.Pods {
		if o.excluded(p.Namespace) {
			continue
		}
		obj := "Pod/" + p.Name

		if p.Status.Phase == corev1.PodPending && !p.CreationTimestamp.IsZero() &&
			now.Sub(p.CreationTimestamp.Time) > threshold {
			reason := "unschedulable or waiting on image/volume"
			for _, cond := range p.Status.Conditions {
				if cond.Type == corev1.PodScheduled && cond.Status == corev1.ConditionFalse && cond.Message != "" {
					reason = cond.Message
				}
			}
			out = append(out, Finding{
				CheckID: c.ID(), Title: c.Title(), Severity: High, Category: Reliability,
				Namespace: p.Namespace, Object: obj,
				Message:     fmt.Sprintf("Pending for %s: %s", now.Sub(p.CreationTimestamp.Time).Round(time.Minute), truncate(reason, 160)),
				Remediation: "Check `kubectl describe pod` events. Usual causes: requests exceed any node, missing PVC/StorageClass, node selector/taint mismatch, or image pull failure.",
			})
		}

		for _, cs := range p.Status.ContainerStatuses {
			if cs.State.Waiting != nil && cs.State.Waiting.Reason == "CrashLoopBackOff" {
				out = append(out, Finding{
					CheckID: c.ID(), Title: c.Title(), Severity: High, Category: Reliability,
					Namespace: p.Namespace, Object: obj,
					Message:     fmt.Sprintf("container %q in CrashLoopBackOff (%d restarts)", cs.Name, cs.RestartCount),
					Remediation: "Inspect `kubectl logs --previous`. If the container exits on a missing dependency, fix startup ordering or add retries instead of relying on restarts.",
				})
			}
			if cs.LastTerminationState.Terminated != nil && cs.LastTerminationState.Terminated.Reason == "OOMKilled" {
				out = append(out, Finding{
					CheckID: c.ID(), Title: c.Title(), Severity: High, Category: Reliability,
					Namespace: p.Namespace, Object: obj,
					Message:     fmt.Sprintf("container %q was OOMKilled (%d restarts)", cs.Name, cs.RestartCount),
					Remediation: "Raise the memory limit to the observed peak plus headroom, or fix the leak. Check for JVM/Node heap flags that ignore cgroup limits.",
				})
			}
			if cs.RestartCount >= 10 && cs.State.Running != nil {
				out = append(out, Finding{
					CheckID: c.ID(), Title: c.Title(), Severity: Medium, Category: Reliability,
					Namespace: p.Namespace, Object: obj,
					Message:     fmt.Sprintf("container %q restarted %d times", cs.Name, cs.RestartCount),
					Remediation: "Frequent restarts hide real failures. Correlate with liveness probe timeouts and resource limits.",
				})
			}
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// ---- orphan PVCs -----------------------------------------------------------

type orphanPVCs struct{}

func (orphanPVCs) ID() string    { return "COST001" }
func (orphanPVCs) Title() string { return "PersistentVolumeClaims not mounted by any pod" }

func (c orphanPVCs) Run(s *snapshot.Snapshot, o Options) []Finding {
	used := map[string]bool{}
	for _, p := range s.Pods {
		for _, v := range p.Spec.Volumes {
			if v.PersistentVolumeClaim != nil {
				used[p.Namespace+"/"+v.PersistentVolumeClaim.ClaimName] = true
			}
		}
	}
	var out []Finding
	var total resource.Quantity
	for _, pvc := range s.PVCs {
		if o.excluded(pvc.Namespace) || used[pvc.Namespace+"/"+pvc.Name] {
			continue
		}
		size := pvc.Spec.Resources.Requests.Storage()
		if size != nil {
			total.Add(*size)
		}
		out = append(out, Finding{
			CheckID: c.ID(), Title: c.Title(), Severity: Medium, Category: Cost,
			Namespace: pvc.Namespace, Object: "PersistentVolumeClaim/" + pvc.Name,
			Message:     fmt.Sprintf("%s (%s) is bound but unused", size.String(), pvc.Status.Phase),
			Remediation: "Confirm the data is not needed (or snapshot it), then delete the PVC. Unmounted volumes are billed every month. Beware StatefulSet PVCs that survive scale-down by design.",
		})
	}
	if len(out) > 1 {
		out = append(out, Finding{
			CheckID: c.ID(), Title: c.Title(), Severity: Low, Category: Cost,
			Object:      "cluster",
			Message:     fmt.Sprintf("%d orphan PVCs totalling %s of billed storage", len(out), total.String()),
			Remediation: "Schedule a monthly orphan-volume review or enable a reclaim job.",
		})
	}
	return out
}

// ---- load balancers --------------------------------------------------------

type loadBalancerSprawl struct{}

func (loadBalancerSprawl) ID() string    { return "COST002" }
func (loadBalancerSprawl) Title() string { return "Many Services of type LoadBalancer" }

func (c loadBalancerSprawl) Run(s *snapshot.Snapshot, o Options) []Finding {
	var lbs []string
	for _, svc := range s.Services {
		if o.excluded(svc.Namespace) || svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
			continue
		}
		lbs = append(lbs, svc.Namespace+"/"+svc.Name)
	}
	if len(lbs) < 3 {
		return nil
	}
	return []Finding{{
		CheckID: c.ID(), Title: c.Title(), Severity: Medium, Category: Cost,
		Object:      "cluster",
		Message:     fmt.Sprintf("%d LoadBalancer services, each a billed cloud LB (~$15–25/month + traffic): %s", len(lbs), strings.Join(lbs, ", ")),
		Remediation: "Route HTTP services through a single Ingress controller / Gateway API with one LB. Keep dedicated LBs only for non-HTTP or isolation requirements.",
	}}
}

// ---- node health -----------------------------------------------------------

type nodeHealth struct{}

func (nodeHealth) ID() string    { return "NODE001" }
func (nodeHealth) Title() string { return "Nodes not Ready or under pressure" }

func (c nodeHealth) Run(s *snapshot.Snapshot, _ Options) []Finding {
	var out []Finding
	for _, n := range s.Nodes {
		for _, cond := range n.Status.Conditions {
			bad := false
			switch cond.Type {
			case corev1.NodeReady:
				bad = cond.Status != corev1.ConditionTrue
			case corev1.NodeMemoryPressure, corev1.NodeDiskPressure, corev1.NodePIDPressure, corev1.NodeNetworkUnavailable:
				bad = cond.Status == corev1.ConditionTrue
			}
			if !bad {
				continue
			}
			sev := High
			if cond.Type == corev1.NodeReady {
				sev = Critical
			}
			out = append(out, Finding{
				CheckID: c.ID(), Title: c.Title(), Severity: sev, Category: Reliability,
				Object:      "Node/" + n.Name,
				Message:     fmt.Sprintf("%s=%s: %s", cond.Type, cond.Status, truncate(cond.Message, 120)),
				Remediation: "Investigate the node (kubelet logs, disk usage, memory). Cordon and drain if it will not recover; check that cluster autoscaler replaces unhealthy nodes.",
			})
		}
	}
	return out
}

// ---- node headroom / overcommit -------------------------------------------

type nodeHeadroom struct{}

func (nodeHeadroom) ID() string    { return "COST003" }
func (nodeHeadroom) Title() string { return "Cluster capacity vs. requested resources" }

func (c nodeHeadroom) Run(s *snapshot.Snapshot, o Options) []Finding {
	if len(s.Nodes) == 0 {
		return nil
	}
	var allocCPU, allocMem, reqCPU, reqMem resource.Quantity
	for _, n := range s.Nodes {
		if n.Spec.Unschedulable {
			continue
		}
		allocCPU.Add(*n.Status.Allocatable.Cpu())
		allocMem.Add(*n.Status.Allocatable.Memory())
	}
	for _, p := range s.Pods {
		if p.Status.Phase != corev1.PodRunning && p.Status.Phase != corev1.PodPending {
			continue
		}
		for _, ct := range p.Spec.Containers {
			reqCPU.Add(*ct.Resources.Requests.Cpu())
			reqMem.Add(*ct.Resources.Requests.Memory())
		}
	}
	if allocCPU.IsZero() || allocMem.IsZero() {
		return nil
	}
	cpuPct := float64(reqCPU.MilliValue()) / float64(allocCPU.MilliValue()) * 100
	memPct := float64(reqMem.Value()) / float64(allocMem.Value()) * 100

	summary := fmt.Sprintf("requests use %.0f%% of allocatable CPU (%s / %s) and %.0f%% of memory (%s / %s) across %d nodes",
		cpuPct, reqCPU.String(), allocCPU.String(), memPct, humanBytes(reqMem.Value()), humanBytes(allocMem.Value()), len(s.Nodes))

	var out []Finding
	switch {
	case cpuPct < 35 && memPct < 35:
		out = append(out, Finding{
			CheckID: c.ID(), Title: c.Title(), Severity: Medium, Category: Cost,
			Object:      "cluster",
			Message:     summary + " — the cluster is likely oversized",
			Remediation: "Enable cluster autoscaler/Karpenter with aggressive scale-down, consolidate onto fewer or smaller nodes, or right-size node pools. This is usually the single largest saving.",
		})
	case cpuPct > 90 || memPct > 90:
		out = append(out, Finding{
			CheckID: c.ID(), Title: c.Title(), Severity: High, Category: Reliability,
			Object:      "cluster",
			Message:     summary + " — little headroom for rollouts or node failure",
			Remediation: "Add capacity or reduce over-requested workloads. With <10% headroom a single node loss leaves pods Pending.",
		})
	default:
		out = append(out, Finding{
			CheckID: c.ID(), Title: c.Title(), Severity: Low, Category: Cost,
			Object:      "cluster",
			Message:     summary,
			Remediation: "Compare requests to actual usage (metrics-server / Prometheus). Requests far above usage are the next place to save.",
		})
	}
	return out
}

func humanBytes(b int64) string {
	const gi = 1 << 30
	if b >= gi {
		return fmt.Sprintf("%.1fGi", float64(b)/gi)
	}
	return fmt.Sprintf("%.0fMi", float64(b)/(1<<20))
}
