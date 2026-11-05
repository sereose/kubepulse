package checks

import (
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/sereose/kubepulse/internal/snapshot"
)

// activeNamespaces returns namespaces that run at least one pod and are not excluded.
func activeNamespaces(s *snapshot.Snapshot, o Options) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range s.Pods {
		if o.excluded(p.Namespace) || seen[p.Namespace] {
			continue
		}
		seen[p.Namespace] = true
		out = append(out, p.Namespace)
	}
	return out
}

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
	var out []Finding
	for _, ns := range activeNamespaces(s, o) {
		var missing []string
		if !hasQuota[ns] {
			missing = append(missing, "ResourceQuota")
		}
		if !hasLR[ns] {
			missing = append(missing, "LimitRange")
		}
		if len(missing) == 0 {
			continue
		}
		out = append(out, Finding{
			CheckID: c.ID(), Title: c.Title(), Severity: Low, Category: Hygiene,
			Namespace: ns, Object: "Namespace/" + ns,
			Message:     "no " + strings.Join(missing, " or "),
			Remediation: "Add a LimitRange with default requests/limits so forgotten resource specs get sane values, and a ResourceQuota to cap what one team can consume.",
		})
	}
	return out
}

// ---- network policy coverage ----------------------------------------------

type networkPolicyCoverage struct{}

func (networkPolicyCoverage) ID() string    { return "NS002" }
func (networkPolicyCoverage) Title() string { return "Namespaces with workloads but no NetworkPolicy" }

func (c networkPolicyCoverage) Run(s *snapshot.Snapshot, o Options) []Finding {
	covered := map[string]bool{}
	for _, np := range s.NetworkPolicies {
		covered[np.Namespace] = true
	}
	var out []Finding
	for _, ns := range activeNamespaces(s, o) {
		if covered[ns] {
			continue
		}
		out = append(out, Finding{
			CheckID: c.ID(), Title: c.Title(), Severity: Medium, Category: Security,
			Namespace: ns, Object: "Namespace/" + ns,
			Message:     "every pod can talk to every other pod in the cluster",
			Remediation: "Add a default-deny ingress NetworkPolicy per namespace, then allow only required flows. Requires a CNI that enforces policies (Calico, Cilium, most managed CNIs).",
		})
	}
	return out
}

// ---- pods: stuck pending ---------------------------------------------------

type pendingPods struct{}

func (pendingPods) ID() string    { return "POD001" }
func (pendingPods) Title() string { return "Pods stuck in Pending" }

func (c pendingPods) Run(s *snapshot.Snapshot, o Options) []Finding {
	threshold := time.Duration(o.PendingThresholdSeconds) * time.Second
	now := s.CollectedAt
	if now.IsZero() {
		now = time.Now()
	}
	var out []Finding
	for _, p := range s.Pods {
		if o.excluded(p.Namespace) || p.Status.Phase != corev1.PodPending || p.CreationTimestamp.IsZero() {
			continue
		}
		age := now.Sub(p.CreationTimestamp.Time)
		if age <= threshold {
			continue
		}
		reason := "unschedulable or waiting on image/volume"
		for _, cond := range p.Status.Conditions {
			if cond.Type == corev1.PodScheduled && cond.Status == corev1.ConditionFalse && cond.Message != "" {
				reason = cond.Message
			}
		}
		out = append(out, Finding{
			CheckID: c.ID(), Title: c.Title(), Severity: High, Category: Reliability,
			Namespace: p.Namespace, Object: "Pod/" + p.Name,
			Message:     fmt.Sprintf("Pending for %s: %s", age.Round(time.Minute), truncate(reason, 160)),
			Remediation: "Check `kubectl describe pod` events. Usual causes: requests exceed any node, missing PVC/StorageClass, node selector/taint mismatch, or image pull failure.",
		})
	}
	return out
}

// ---- pods: crash loop ------------------------------------------------------

type crashLoopPods struct{}

func (crashLoopPods) ID() string    { return "POD002" }
func (crashLoopPods) Title() string { return "Containers in CrashLoopBackOff" }

func (c crashLoopPods) Run(s *snapshot.Snapshot, o Options) []Finding {
	var out []Finding
	for _, p := range s.Pods {
		if o.excluded(p.Namespace) {
			continue
		}
		for _, cs := range p.Status.ContainerStatuses {
			if cs.State.Waiting == nil || cs.State.Waiting.Reason != "CrashLoopBackOff" {
				continue
			}
			out = append(out, Finding{
				CheckID: c.ID(), Title: c.Title(), Severity: High, Category: Reliability,
				Namespace: p.Namespace, Object: "Pod/" + p.Name,
				Message:     fmt.Sprintf("container %q in CrashLoopBackOff (%d restarts)", cs.Name, cs.RestartCount),
				Remediation: "Inspect `kubectl logs --previous`. If the container exits on a missing dependency, fix startup ordering or add retries instead of relying on restarts.",
			})
		}
	}
	return out
}

// ---- pods: OOMKilled -------------------------------------------------------

type oomKilledPods struct{}

func (oomKilledPods) ID() string    { return "POD003" }
func (oomKilledPods) Title() string { return "Containers recently OOMKilled" }

func (c oomKilledPods) Run(s *snapshot.Snapshot, o Options) []Finding {
	var out []Finding
	for _, p := range s.Pods {
		if o.excluded(p.Namespace) {
			continue
		}
		for _, cs := range p.Status.ContainerStatuses {
			t := cs.LastTerminationState.Terminated
			if t == nil || t.Reason != "OOMKilled" {
				continue
			}
			out = append(out, Finding{
				CheckID: c.ID(), Title: c.Title(), Severity: High, Category: Reliability,
				Namespace: p.Namespace, Object: "Pod/" + p.Name,
				Message:     fmt.Sprintf("container %q was OOMKilled (%d restarts)", cs.Name, cs.RestartCount),
				Remediation: "Raise the memory limit to the observed peak plus headroom, or fix the leak. Check for JVM/Node heap flags that ignore cgroup limits.",
			})
		}
	}
	return out
}

// ---- pods: restart storm ---------------------------------------------------

type restartStorm struct{}

func (restartStorm) ID() string    { return "POD004" }
func (restartStorm) Title() string { return "Containers with many restarts" }

func (c restartStorm) Run(s *snapshot.Snapshot, o Options) []Finding {
	var out []Finding
	for _, p := range s.Pods {
		if o.excluded(p.Namespace) {
			continue
		}
		for _, cs := range p.Status.ContainerStatuses {
			if cs.RestartCount < 10 || cs.State.Running == nil {
				continue
			}
			// Skip if another check already explains the restarts.
			if cs.LastTerminationState.Terminated != nil && cs.LastTerminationState.Terminated.Reason == "OOMKilled" {
				continue
			}
			out = append(out, Finding{
				CheckID: c.ID(), Title: c.Title(), Severity: Medium, Category: Reliability,
				Namespace: p.Namespace, Object: "Pod/" + p.Name,
				Message:     fmt.Sprintf("container %q restarted %d times and is currently running", cs.Name, cs.RestartCount),
				Remediation: "Frequent restarts hide real failures. Correlate with liveness probe timeouts, resource limits and dependency outages.",
			})
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
		msg := fmt.Sprintf("%d orphan PVCs totalling %s of billed storage", len(out), total.String())
		if o.StorageMonthlyCostPerGi > 0 {
			gi := float64(total.Value()) / (1 << 30)
			msg += fmt.Sprintf(" (~$%.0f/month at $%.2f/Gi)", gi*o.StorageMonthlyCostPerGi, o.StorageMonthlyCostPerGi)
		}
		out = append(out, Finding{
			CheckID: c.ID(), Title: c.Title(), Severity: Low, Category: Cost,
			Object:      "cluster",
			Message:     msg,
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

// ---- ingress TLS -----------------------------------------------------------

type ingressWithoutTLS struct{}

func (ingressWithoutTLS) ID() string    { return "SEC005" }
func (ingressWithoutTLS) Title() string { return "Ingress hosts without TLS" }

func (c ingressWithoutTLS) Run(s *snapshot.Snapshot, o Options) []Finding {
	var out []Finding
	for _, ing := range s.Ingresses {
		if o.excluded(ing.Namespace) {
			continue
		}
		tlsHosts := map[string]bool{}
		for _, t := range ing.Spec.TLS {
			for _, h := range t.Hosts {
				tlsHosts[h] = true
			}
		}
		var plain []string
		for _, r := range ing.Spec.Rules {
			if r.Host == "" {
				if len(ing.Spec.TLS) == 0 {
					plain = append(plain, "(any host)")
				}
				continue
			}
			if !tlsHosts[r.Host] {
				plain = append(plain, r.Host)
			}
		}
		if len(plain) == 0 {
			continue
		}
		out = append(out, Finding{
			CheckID: c.ID(), Title: c.Title(), Severity: High, Category: Security,
			Namespace: ing.Namespace, Object: "Ingress/" + ing.Name,
			Message:     "no TLS section for host(s): " + strings.Join(plain, ", "),
			Remediation: "Add spec.tls with a certificate (cert-manager + Let's Encrypt is free) and redirect HTTP to HTTPS at the ingress controller. If TLS terminates at a cloud LB in front, document it and suppress this finding.",
		})
	}
	return out
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
	schedulable := 0
	for _, n := range s.Nodes {
		if n.Spec.Unschedulable {
			continue
		}
		schedulable++
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

	summary := fmt.Sprintf("requests use %.0f%% of allocatable CPU (%s / %s) and %.0f%% of memory (%s / %s) across %d schedulable nodes",
		cpuPct, reqCPU.String(), allocCPU.String(), memPct, humanBytes(reqMem.Value()), humanBytes(allocMem.Value()), schedulable)

	// Idle share = capacity not covered by the busier of the two dimensions.
	busiest := cpuPct
	if memPct > busiest {
		busiest = memPct
	}
	idleShare := 1 - busiest/100
	if idleShare < 0 {
		idleShare = 0
	}
	costNote := ""
	if o.NodeMonthlyCost > 0 {
		idle := idleShare * float64(schedulable) * o.NodeMonthlyCost
		costNote = fmt.Sprintf("; ~$%.0f/month of node capacity is unrequested (at $%.0f/node/month)", idle, o.NodeMonthlyCost)
	}

	var out []Finding
	switch {
	case cpuPct < 35 && memPct < 35:
		out = append(out, Finding{
			CheckID: c.ID(), Title: c.Title(), Severity: Medium, Category: Cost,
			Object:      "cluster",
			Message:     summary + " — the cluster is likely oversized" + costNote,
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
			Message:     summary + costNote,
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
