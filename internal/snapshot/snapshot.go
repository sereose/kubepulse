// Package snapshot collects a read-only, point-in-time view of a cluster.
//
// All checks operate on a Snapshot rather than on a live client. This keeps
// checks trivially testable, makes audits reproducible, and lets a prospect
// run `kubepulse --save` and send the JSON instead of granting cluster access.
package snapshot

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Options controls how a snapshot is collected.
type Options struct {
	Kubeconfig string
	Context    string
	Namespace  string // empty = all namespaces
}

// Snapshot is everything the checks need. Only read-only list calls are used.
type Snapshot struct {
	CollectedAt   time.Time `json:"collectedAt"`
	ServerVersion string    `json:"serverVersion"`
	ContextName   string    `json:"contextName,omitempty"`

	Namespaces     []corev1.Namespace                    `json:"namespaces"`
	Nodes          []corev1.Node                         `json:"nodes"`
	Pods           []corev1.Pod                          `json:"pods"`
	Deployments    []appsv1.Deployment                   `json:"deployments"`
	StatefulSets   []appsv1.StatefulSet                  `json:"statefulSets"`
	DaemonSets     []appsv1.DaemonSet                    `json:"daemonSets"`
	Services       []corev1.Service                      `json:"services"`
	PVCs           []corev1.PersistentVolumeClaim        `json:"pvcs"`
	PDBs           []policyv1.PodDisruptionBudget        `json:"pdbs"`
	HPAs           []autoscalingv2.HorizontalPodAutoscaler `json:"hpas"`
	ResourceQuotas []corev1.ResourceQuota                `json:"resourceQuotas"`
	LimitRanges    []corev1.LimitRange                   `json:"limitRanges"`

	// Warnings records non-fatal collection problems (e.g. RBAC denied a list).
	Warnings []string `json:"warnings,omitempty"`
}

// Collect queries the cluster and returns a Snapshot. Individual list failures
// are recorded as warnings rather than aborting the audit, because a prospect's
// RBAC frequently forbids some resource types.
func Collect(ctx context.Context, opts Options) (*Snapshot, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if opts.Kubeconfig != "" {
		rules.ExplicitPath = opts.Kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: opts.Context}
	cfg := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)

	restCfg, err := cfg.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("kubeconfig: %w", err)
	}
	restCfg.QPS = 50
	restCfg.Burst = 100

	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, err
	}

	snap := &Snapshot{CollectedAt: time.Now().UTC()}
	if raw, err := cfg.RawConfig(); err == nil {
		snap.ContextName = raw.CurrentContext
		if opts.Context != "" {
			snap.ContextName = opts.Context
		}
	}
	if v, err := cs.Discovery().ServerVersion(); err == nil {
		snap.ServerVersion = v.GitVersion
	} else {
		snap.warn("server version: %v", err)
	}

	ns := opts.Namespace
	lo := metav1.ListOptions{}

	// Cluster-scoped.
	if l, err := cs.CoreV1().Namespaces().List(ctx, lo); err == nil {
		snap.Namespaces = l.Items
	} else {
		snap.warn("list namespaces: %v", err)
	}
	if l, err := cs.CoreV1().Nodes().List(ctx, lo); err == nil {
		snap.Nodes = l.Items
	} else {
		snap.warn("list nodes: %v", err)
	}

	// Namespaced (ns == "" means all).
	if l, err := cs.CoreV1().Pods(ns).List(ctx, lo); err == nil {
		snap.Pods = l.Items
	} else {
		snap.warn("list pods: %v", err)
	}
	if l, err := cs.AppsV1().Deployments(ns).List(ctx, lo); err == nil {
		snap.Deployments = l.Items
	} else {
		snap.warn("list deployments: %v", err)
	}
	if l, err := cs.AppsV1().StatefulSets(ns).List(ctx, lo); err == nil {
		snap.StatefulSets = l.Items
	} else {
		snap.warn("list statefulsets: %v", err)
	}
	if l, err := cs.AppsV1().DaemonSets(ns).List(ctx, lo); err == nil {
		snap.DaemonSets = l.Items
	} else {
		snap.warn("list daemonsets: %v", err)
	}
	if l, err := cs.CoreV1().Services(ns).List(ctx, lo); err == nil {
		snap.Services = l.Items
	} else {
		snap.warn("list services: %v", err)
	}
	if l, err := cs.CoreV1().PersistentVolumeClaims(ns).List(ctx, lo); err == nil {
		snap.PVCs = l.Items
	} else {
		snap.warn("list pvcs: %v", err)
	}
	if l, err := cs.PolicyV1().PodDisruptionBudgets(ns).List(ctx, lo); err == nil {
		snap.PDBs = l.Items
	} else {
		snap.warn("list pdbs: %v", err)
	}
	if l, err := cs.AutoscalingV2().HorizontalPodAutoscalers(ns).List(ctx, lo); err == nil {
		snap.HPAs = l.Items
	} else {
		snap.warn("list hpas: %v", err)
	}
	if l, err := cs.CoreV1().ResourceQuotas(ns).List(ctx, lo); err == nil {
		snap.ResourceQuotas = l.Items
	} else {
		snap.warn("list resourcequotas: %v", err)
	}
	if l, err := cs.CoreV1().LimitRanges(ns).List(ctx, lo); err == nil {
		snap.LimitRanges = l.Items
	} else {
		snap.warn("list limitranges: %v", err)
	}

	// Strip bulky, irrelevant fields so saved snapshots stay small and shareable.
	snap.scrub()
	return snap, nil
}

func (s *Snapshot) warn(format string, args ...any) {
	s.Warnings = append(s.Warnings, fmt.Sprintf(format, args...))
}

// scrub removes managedFields and last-applied annotations. These can be
// hundreds of KB per object and never inform a check.
func (s *Snapshot) scrub() {
	clean := func(om *metav1.ObjectMeta) {
		om.ManagedFields = nil
		delete(om.Annotations, "kubectl.kubernetes.io/last-applied-configuration")
	}
	for i := range s.Namespaces {
		clean(&s.Namespaces[i].ObjectMeta)
	}
	for i := range s.Nodes {
		clean(&s.Nodes[i].ObjectMeta)
		s.Nodes[i].Status.Images = nil
	}
	for i := range s.Pods {
		clean(&s.Pods[i].ObjectMeta)
	}
	for i := range s.Deployments {
		clean(&s.Deployments[i].ObjectMeta)
	}
	for i := range s.StatefulSets {
		clean(&s.StatefulSets[i].ObjectMeta)
	}
	for i := range s.DaemonSets {
		clean(&s.DaemonSets[i].ObjectMeta)
	}
	for i := range s.Services {
		clean(&s.Services[i].ObjectMeta)
	}
	for i := range s.PVCs {
		clean(&s.PVCs[i].ObjectMeta)
	}
	for i := range s.PDBs {
		clean(&s.PDBs[i].ObjectMeta)
	}
	for i := range s.HPAs {
		clean(&s.HPAs[i].ObjectMeta)
	}
	for i := range s.ResourceQuotas {
		clean(&s.ResourceQuotas[i].ObjectMeta)
	}
	for i := range s.LimitRanges {
		clean(&s.LimitRanges[i].ObjectMeta)
	}
}

// SaveFile writes the snapshot as indented JSON.
func (s *Snapshot) SaveFile(path string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// LoadFile reads a snapshot previously written by SaveFile.
func LoadFile(path string) (*Snapshot, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &s, nil
}
