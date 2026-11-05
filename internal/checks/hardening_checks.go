package checks

import (
	"fmt"
	"strings"

	"github.com/sereose/kubepulse/internal/snapshot"
)

// ---- service account token -------------------------------------------------

type serviceAccountToken struct{}

func (serviceAccountToken) ID() string    { return "SEC004" }
func (serviceAccountToken) Title() string { return "Default ServiceAccount token mounted into pods" }

// Flags workloads that run as the namespace's default ServiceAccount and still
// mount its API token. Such a pod that gets compromised can talk to the API
// server with whatever the default SA is allowed to do.
func (c serviceAccountToken) Run(s *snapshot.Snapshot, o Options) []Finding {
	var out []Finding
	for _, w := range workloads(s, o) {
		sp := w.Template.Spec
		sa := sp.ServiceAccountName
		if sa == "" {
			sa = sp.DeprecatedServiceAccount
		}
		if sa != "" && sa != "default" {
			continue
		}
		if sp.AutomountServiceAccountToken != nil && !*sp.AutomountServiceAccountToken {
			continue
		}
		out = append(out, Finding{
			CheckID: c.ID(), Title: c.Title(), Severity: Medium, Category: Security,
			Namespace: w.Namespace, Object: w.ref(),
			Message:     "runs as the default ServiceAccount with its API token auto-mounted",
			Remediation: "Set automountServiceAccountToken: false on pods that do not call the Kubernetes API. Workloads that do need the API should use a dedicated ServiceAccount with a minimal Role.",
		})
	}
	return out
}

// ---- container hardening ---------------------------------------------------

type containerHardening struct{}

func (containerHardening) ID() string    { return "SEC006" }
func (containerHardening) Title() string { return "Containers missing baseline hardening" }

// Low-severity, high-volume: allowPrivilegeEscalation left on, writable root
// filesystem, no dropped capabilities. Individually minor; together they are
// the difference between "contained" and "one CVE from the node".
func (c containerHardening) Run(s *snapshot.Snapshot, o Options) []Finding {
	var out []Finding
	for _, w := range workloads(s, o) {
		for _, ct := range w.Template.Spec.Containers {
			sc := ct.SecurityContext
			var gaps []string
			if sc == nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
				gaps = append(gaps, "allowPrivilegeEscalation not false")
			}
			if sc == nil || sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
				gaps = append(gaps, "root filesystem writable")
			}
			if sc == nil || sc.Capabilities == nil || !dropsAll(sc.Capabilities.Drop) {
				gaps = append(gaps, "capabilities not dropped")
			}
			if len(gaps) == 0 {
				continue
			}
			out = append(out, Finding{
				CheckID: c.ID(), Title: c.Title(), Severity: Low, Category: Security,
				Namespace: w.Namespace, Object: w.ref(),
				Message:     fmt.Sprintf("container %q: %s", ct.Name, strings.Join(gaps, "; ")),
				Remediation: "Set securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}} and mount an emptyDir where the app needs to write. Matches the Pod Security 'restricted' profile.",
			})
		}
	}
	return out
}

func dropsAll(drop []corev1Capability) bool {
	for _, d := range drop {
		if strings.EqualFold(string(d), "ALL") {
			return true
		}
	}
	return false
}

// ---- anti-affinity ---------------------------------------------------------

type missingAntiAffinity struct{}

func (missingAntiAffinity) ID() string    { return "WL006" }
func (missingAntiAffinity) Title() string { return "Multi-replica workloads without spreading across nodes" }

// Two replicas on the same node are one node failure away from zero.
func (c missingAntiAffinity) Run(s *snapshot.Snapshot, o Options) []Finding {
	if len(s.Nodes) < 2 {
		return nil // nothing to spread across
	}
	var out []Finding
	for _, w := range workloads(s, o) {
		if w.Replicas < 2 {
			continue
		}
		sp := w.Template.Spec
		if len(sp.TopologySpreadConstraints) > 0 {
			continue
		}
		if sp.Affinity != nil && sp.Affinity.PodAntiAffinity != nil {
			aa := sp.Affinity.PodAntiAffinity
			if len(aa.RequiredDuringSchedulingIgnoredDuringExecution) > 0 || len(aa.PreferredDuringSchedulingIgnoredDuringExecution) > 0 {
				continue
			}
		}
		out = append(out, Finding{
			CheckID: c.ID(), Title: c.Title(), Severity: Medium, Category: Reliability,
			Namespace: w.Namespace, Object: w.ref(),
			Message:     fmt.Sprintf("%d replicas with no podAntiAffinity or topologySpreadConstraints — they may all land on one node", w.Replicas),
			Remediation: "Add topologySpreadConstraints on topology.kubernetes.io/zone and kubernetes.io/hostname (whenUnsatisfiable: ScheduleAnyway), or a preferred podAntiAffinity on hostname.",
		})
	}
	return out
}
