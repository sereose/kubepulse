package checks

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/sereose/kubepulse/internal/snapshot"
)

// ---- resource requests / limits -------------------------------------------

type resourceRequests struct{}

func (resourceRequests) ID() string    { return "WL001" }
func (resourceRequests) Title() string { return "Containers without resource requests/limits" }

func (c resourceRequests) Run(s *snapshot.Snapshot, o Options) []Finding {
	var out []Finding
	for _, w := range workloads(s, o) {
		for _, ct := range w.Template.Spec.Containers {
			var missing []string
			if ct.Resources.Requests.Cpu().IsZero() {
				missing = append(missing, "cpu request")
			}
			if ct.Resources.Requests.Memory().IsZero() {
				missing = append(missing, "memory request")
			}
			if ct.Resources.Limits.Memory().IsZero() {
				missing = append(missing, "memory limit")
			}
			if len(missing) == 0 {
				continue
			}
			sev := Medium
			if len(missing) == 3 {
				sev = High
			}
			out = append(out, Finding{
				CheckID: c.ID(), Title: c.Title(), Severity: sev, Category: Reliability,
				Namespace: w.Namespace, Object: w.ref(),
				Message:     fmt.Sprintf("container %q is missing %s", ct.Name, strings.Join(missing, ", ")),
				Remediation: "Set requests (cpu, memory) and a memory limit. Without requests the scheduler cannot place pods safely and cost allocation is impossible; without a memory limit one leak can evict neighbours.",
			})
		}
	}
	return out
}

// ---- single replica --------------------------------------------------------

type singleReplica struct{}

func (singleReplica) ID() string    { return "WL002" }
func (singleReplica) Title() string { return "Workloads with a single replica" }

func (c singleReplica) Run(s *snapshot.Snapshot, o Options) []Finding {
	var out []Finding
	for _, w := range workloads(s, o) {
		if w.Replicas != 1 || w.Kind == "DaemonSet" {
			continue
		}
		out = append(out, Finding{
			CheckID: c.ID(), Title: c.Title(), Severity: Medium, Category: Reliability,
			Namespace: w.Namespace, Object: w.ref(),
			Message:     "replicas=1: any node drain, OOM or rollout causes downtime",
			Remediation: "Run at least 2 replicas for anything user-facing, add a PodDisruptionBudget and pod anti-affinity across nodes. If it truly must be a singleton, document why.",
		})
	}
	return out
}

// ---- probes ----------------------------------------------------------------

type missingProbes struct{}

func (missingProbes) ID() string    { return "WL003" }
func (missingProbes) Title() string { return "Containers without liveness/readiness probes" }

func (c missingProbes) Run(s *snapshot.Snapshot, o Options) []Finding {
	var out []Finding
	for _, w := range workloads(s, o) {
		for _, ct := range w.Template.Spec.Containers {
			var missing []string
			if ct.ReadinessProbe == nil {
				missing = append(missing, "readiness")
			}
			if ct.LivenessProbe == nil {
				missing = append(missing, "liveness")
			}
			if len(missing) == 0 {
				continue
			}
			out = append(out, Finding{
				CheckID: c.ID(), Title: c.Title(), Severity: Medium, Category: Reliability,
				Namespace: w.Namespace, Object: w.ref(),
				Message:     fmt.Sprintf("container %q has no %s probe", ct.Name, strings.Join(missing, "/")),
				Remediation: "Add a readiness probe so traffic only reaches healthy pods during rollouts, and a liveness probe so hung processes are restarted. Avoid pointing liveness at dependencies (DB) to prevent cascading restarts.",
			})
		}
	}
	return out
}

// ---- image tags ------------------------------------------------------------

type latestImageTag struct{}

func (latestImageTag) ID() string    { return "WL004" }
func (latestImageTag) Title() string { return "Images using :latest or no tag" }

func (c latestImageTag) Run(s *snapshot.Snapshot, o Options) []Finding {
	var out []Finding
	for _, w := range workloads(s, o) {
		for _, ct := range allContainers(w.Template) {
			if !isMutableTag(ct.Image) {
				continue
			}
			out = append(out, Finding{
				CheckID: c.ID(), Title: c.Title(), Severity: Medium, Category: Hygiene,
				Namespace: w.Namespace, Object: w.ref(),
				Message:     fmt.Sprintf("container %q uses image %q", ct.Name, ct.Image),
				Remediation: "Pin images to an immutable tag or digest. Mutable tags make rollbacks impossible and let a registry push silently change production.",
			})
		}
	}
	return out
}

// isMutableTag reports whether an image reference lacks a tag or uses :latest.
func isMutableTag(image string) bool {
	if strings.Contains(image, "@sha256:") {
		return false
	}
	// Strip registry host (may contain a port) before looking for the tag colon.
	rest := image
	if i := strings.LastIndex(image, "/"); i >= 0 {
		rest = image[i+1:]
	}
	i := strings.LastIndex(rest, ":")
	if i < 0 {
		return true
	}
	return rest[i+1:] == "latest"
}

// ---- privileged ------------------------------------------------------------

type privilegedContainers struct{}

func (privilegedContainers) ID() string    { return "SEC001" }
func (privilegedContainers) Title() string { return "Privileged containers" }

func (c privilegedContainers) Run(s *snapshot.Snapshot, o Options) []Finding {
	var out []Finding
	for _, w := range workloads(s, o) {
		for _, ct := range allContainers(w.Template) {
			sc := ct.SecurityContext
			if sc == nil || sc.Privileged == nil || !*sc.Privileged {
				continue
			}
			out = append(out, Finding{
				CheckID: c.ID(), Title: c.Title(), Severity: Critical, Category: Security,
				Namespace: w.Namespace, Object: w.ref(),
				Message:     fmt.Sprintf("container %q runs privileged", ct.Name),
				Remediation: "Drop privileged: true. Grant only the specific capabilities needed (securityContext.capabilities.add) or move the workload to a dedicated node pool with a Pod Security Admission policy.",
			})
		}
	}
	return out
}

// ---- run as root -----------------------------------------------------------

type runAsRoot struct{}

func (runAsRoot) ID() string    { return "SEC002" }
func (runAsRoot) Title() string { return "Containers allowed to run as root" }

func (c runAsRoot) Run(s *snapshot.Snapshot, o Options) []Finding {
	var out []Finding
	for _, w := range workloads(s, o) {
		podSC := w.Template.Spec.SecurityContext
		for _, ct := range w.Template.Spec.Containers {
			if nonRootEnforced(podSC, ct.SecurityContext) {
				continue
			}
			out = append(out, Finding{
				CheckID: c.ID(), Title: c.Title(), Severity: High, Category: Security,
				Namespace: w.Namespace, Object: w.ref(),
				Message:     fmt.Sprintf("container %q does not set runAsNonRoot or a non-zero runAsUser", ct.Name),
				Remediation: "Set securityContext.runAsNonRoot: true (and a numeric runAsUser) at pod or container level. Also consider readOnlyRootFilesystem and allowPrivilegeEscalation: false.",
			})
		}
	}
	return out
}

func nonRootEnforced(pod *corev1.PodSecurityContext, ct *corev1.SecurityContext) bool {
	if ct != nil {
		if ct.RunAsNonRoot != nil && *ct.RunAsNonRoot {
			return true
		}
		if ct.RunAsUser != nil && *ct.RunAsUser != 0 {
			return true
		}
	}
	if pod != nil {
		if pod.RunAsNonRoot != nil && *pod.RunAsNonRoot {
			return true
		}
		if pod.RunAsUser != nil && *pod.RunAsUser != 0 {
			return true
		}
	}
	return false
}

// ---- host namespaces -------------------------------------------------------

type hostNamespaces struct{}

func (hostNamespaces) ID() string    { return "SEC003" }
func (hostNamespaces) Title() string { return "Pods sharing host network/PID/IPC" }

func (c hostNamespaces) Run(s *snapshot.Snapshot, o Options) []Finding {
	var out []Finding
	for _, w := range workloads(s, o) {
		sp := w.Template.Spec
		var shared []string
		if sp.HostNetwork {
			shared = append(shared, "hostNetwork")
		}
		if sp.HostPID {
			shared = append(shared, "hostPID")
		}
		if sp.HostIPC {
			shared = append(shared, "hostIPC")
		}
		if len(shared) == 0 {
			continue
		}
		sev := High
		if w.Kind == "DaemonSet" {
			sev = Medium // agents (CNI, node-exporter) legitimately need this
		}
		out = append(out, Finding{
			CheckID: c.ID(), Title: c.Title(), Severity: sev, Category: Security,
			Namespace: w.Namespace, Object: w.ref(),
			Message:     fmt.Sprintf("pod spec enables %s", strings.Join(shared, ", ")),
			Remediation: "Remove host namespace sharing unless this is an infrastructure agent. Host namespaces bypass network policies and expose the node's processes.",
		})
	}
	return out
}

// ---- PDB -------------------------------------------------------------------

type missingPDB struct{}

func (missingPDB) ID() string    { return "WL005" }
func (missingPDB) Title() string { return "Multi-replica workloads without a PodDisruptionBudget" }

func (c missingPDB) Run(s *snapshot.Snapshot, o Options) []Finding {
	var out []Finding
	for _, w := range workloads(s, o) {
		if w.Replicas < 2 {
			continue
		}
		if hasPDB(s, w) {
			continue
		}
		out = append(out, Finding{
			CheckID: c.ID(), Title: c.Title(), Severity: Medium, Category: Reliability,
			Namespace: w.Namespace, Object: w.ref(),
			Message:     fmt.Sprintf("%d replicas but no PDB selects these pods", w.Replicas),
			Remediation: "Add a PodDisruptionBudget (e.g. minAvailable: 1 or maxUnavailable: 25%) so node upgrades and autoscaler scale-downs cannot evict all replicas at once.",
		})
	}
	return out
}

func hasPDB(s *snapshot.Snapshot, w workload) bool {
	for _, pdb := range s.PDBs {
		if pdb.Namespace != w.Namespace || pdb.Spec.Selector == nil {
			continue
		}
		if matchLabels(pdb.Spec.Selector.MatchLabels, w.Labels) {
			return true
		}
	}
	return false
}

// matchLabels is a simplified selector match (matchLabels only). Good enough
// for an audit; expression selectors are rare on PDBs.
func matchLabels(sel, labels map[string]string) bool {
	if len(sel) == 0 {
		return false
	}
	for k, v := range sel {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// ---- HPA -------------------------------------------------------------------

type missingHPA struct{}

func (missingHPA) ID() string    { return "COST004" }
func (missingHPA) Title() string { return "Deployments with ≥3 fixed replicas and no HPA" }

func (c missingHPA) Run(s *snapshot.Snapshot, o Options) []Finding {
	targets := map[string]bool{}
	for _, h := range s.HPAs {
		targets[h.Namespace+"/"+h.Spec.ScaleTargetRef.Kind+"/"+h.Spec.ScaleTargetRef.Name] = true
	}
	var out []Finding
	for _, w := range workloads(s, o) {
		if w.Kind != "Deployment" || w.Replicas < 3 {
			continue
		}
		if targets[w.Namespace+"/"+w.Kind+"/"+w.Name] {
			continue
		}
		out = append(out, Finding{
			CheckID: c.ID(), Title: c.Title(), Severity: Low, Category: Cost,
			Namespace: w.Namespace, Object: w.ref(),
			Message:     fmt.Sprintf("%d replicas pinned; capacity is paid for 24/7 regardless of load", w.Replicas),
			Remediation: "Add a HorizontalPodAutoscaler on CPU/memory or a custom metric so replicas follow traffic. Pair with cluster autoscaler/Karpenter to actually release nodes.",
		})
	}
	return out
}
