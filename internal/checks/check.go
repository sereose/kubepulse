// Package checks contains the audit rules. Each Check inspects a Snapshot and
// returns zero or more Findings. Checks never talk to the cluster.
package checks

import (
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"

	"github.com/sereose/kubepulse/internal/snapshot"
)

// Severity orders findings and drives the score penalty.
type Severity int

const (
	Low Severity = iota
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Critical:
		return "CRITICAL"
	case High:
		return "HIGH"
	case Medium:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// MarshalText makes Severity serialize as its name in JSON.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Penalty is the score deduction per finding of this severity.
func (s Severity) Penalty() int {
	switch s {
	case Critical:
		return 15
	case High:
		return 8
	case Medium:
		return 3
	default:
		return 1
	}
}

// Category groups findings in the report.
type Category string

const (
	Reliability Category = "Reliability"
	Security    Category = "Security"
	Cost        Category = "Cost"
	Hygiene     Category = "Hygiene"
)

// Finding is one concrete problem with one concrete remediation.
type Finding struct {
	CheckID     string   `json:"checkId"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Category    Category `json:"category"`
	Namespace   string   `json:"namespace,omitempty"`
	Object      string   `json:"object,omitempty"` // kind/name
	Message     string   `json:"message"`
	Remediation string   `json:"remediation"`
}

// Check is a single audit rule.
type Check interface {
	ID() string
	Title() string
	Run(s *snapshot.Snapshot, o Options) []Finding
}

// Options tunes every check.
type Options struct {
	ExcludedNamespaces []string
	// PendingThresholdSeconds marks a Pending pod as stuck after this long.
	PendingThresholdSeconds int
	// NodeMonthlyCost, when > 0, lets cost checks express idle capacity in $.
	NodeMonthlyCost float64
	// StorageMonthlyCostPerGi, when > 0, prices orphan volumes.
	StorageMonthlyCostPerGi float64
}

func (o Options) excluded(ns string) bool {
	for _, e := range o.ExcludedNamespaces {
		if e == ns {
			return true
		}
	}
	return false
}

// Registry is the ordered list of checks executed by RunAll.
var Registry = []Check{
	// Workloads
	resourceRequests{},
	singleReplica{},
	missingProbes{},
	latestImageTag{},
	missingPDB{},
	missingAntiAffinity{},
	// Security
	privilegedContainers{},
	runAsRoot{},
	hostNamespaces{},
	serviceAccountToken{},
	containerHardening{},
	ingressWithoutTLS{},
	// Namespaces
	namespaceGuardrails{},
	networkPolicyCoverage{},
	// Pods
	pendingPods{},
	crashLoopPods{},
	oomKilledPods{},
	restartStorm{},
	// Cost
	orphanPVCs{},
	loadBalancerSprawl{},
	nodeHeadroom{},
	missingHPA{},
	// Nodes
	nodeHealth{},
}

// RunAll executes every registered check and returns findings sorted by
// severity (desc), then category, namespace, object.
func RunAll(s *snapshot.Snapshot, o Options) []Finding {
	if o.PendingThresholdSeconds == 0 {
		o.PendingThresholdSeconds = 600
	}
	var all []Finding
	for _, c := range Registry {
		all = append(all, c.Run(s, o)...)
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Severity != all[j].Severity {
			return all[i].Severity > all[j].Severity
		}
		if all[i].Category != all[j].Category {
			return all[i].Category < all[j].Category
		}
		if all[i].Namespace != all[j].Namespace {
			return all[i].Namespace < all[j].Namespace
		}
		return all[i].Object < all[j].Object
	})
	return all
}

// workload is a uniform view over Deployments/StatefulSets/DaemonSets so
// pod-template checks are written once.
type workload struct {
	Kind      string
	Name      string
	Namespace string
	Replicas  int32 // -1 for DaemonSets
	Template  corev1.PodTemplateSpec
	Labels    map[string]string
}

func (w workload) ref() string { return fmt.Sprintf("%s/%s", w.Kind, w.Name) }

func workloads(s *snapshot.Snapshot, o Options) []workload {
	var out []workload
	for _, d := range s.Deployments {
		if o.excluded(d.Namespace) {
			continue
		}
		r := int32(1)
		if d.Spec.Replicas != nil {
			r = *d.Spec.Replicas
		}
		out = append(out, workload{"Deployment", d.Name, d.Namespace, r, d.Spec.Template, d.Spec.Template.Labels})
	}
	for _, st := range s.StatefulSets {
		if o.excluded(st.Namespace) {
			continue
		}
		r := int32(1)
		if st.Spec.Replicas != nil {
			r = *st.Spec.Replicas
		}
		out = append(out, workload{"StatefulSet", st.Name, st.Namespace, r, st.Spec.Template, st.Spec.Template.Labels})
	}
	for _, ds := range s.DaemonSets {
		if o.excluded(ds.Namespace) {
			continue
		}
		out = append(out, workload{"DaemonSet", ds.Name, ds.Namespace, -1, ds.Spec.Template, ds.Spec.Template.Labels})
	}
	return out
}

type corev1Capability = corev1.Capability

func allContainers(t corev1.PodTemplateSpec) []corev1.Container {
	return append(append([]corev1.Container{}, t.Spec.InitContainers...), t.Spec.Containers...)
}
