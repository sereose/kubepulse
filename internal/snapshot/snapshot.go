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
	networkingv1 "k8s.io/api/networking/v1"
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

	Namespaces      []corev1.Namespace                      `json:"namespaces"`
	Nodes           []corev1.Node                           `json:"nodes"`
	Pods            []corev1.Pod                            `json:"pods"`
	Deployments     []appsv1.Deployment                     `json:"deployments"`
	StatefulSets    []appsv1.StatefulSet                    `json:"statefulSets"`
	DaemonSets      []appsv1.DaemonSet                      `json:"daemonSets"`
	Services        []corev1.Service                        `json:"services"`
	PVCs            []corev1.PersistentVolumeClaim          `json:"pvcs"`
	PDBs            []policyv1.PodDisruptionBudget          `json:"pdbs"`
	HPAs            []autoscalingv2.HorizontalPodAutoscaler `json:"hpas"`
	ResourceQuotas  []corev1.ResourceQuota                  `json:"resourceQuotas"`
	LimitRanges     []corev1.LimitRange                     `json:"limitRanges"`
	NetworkPolicies []networkingv1.NetworkPolicy            `json:"networkPolicies"`
	Ingresses       []networkingv1.Ingress                  `json:"ingresses"`

	// Warnings records non-fatal collection problems (e.g. RBAC denied a list).
	Warnings []string `json:"warnings,omitempty"`
}

// Collect builds a clientset from kubeconfig and delegates to CollectFrom.
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
	restCfg.UserAgent = "kubepulse"

	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, err
	}

	snap, err := CollectFrom(ctx, cs, opts)
	if err != nil {
		return nil, err
	}
	if raw, err := cfg.RawConfig(); err == nil {
		snap.ContextName = raw.CurrentContext
		if opts.Context != "" {
			snap.ContextName = opts.Context
		}
	}
	return snap, nil
}

// CollectFrom queries the cluster through an existing clientset. Individual
// list failures are recorded as warnings rather than aborting the audit,
// because a prospect's RBAC frequently forbids some resource types.
func CollectFrom(ctx context.Context, cs kubernetes.Interface, opts Options) (*Snapshot, error) {
	snap := &Snapshot{CollectedAt: time.Now().UTC()}

	// Pods are the one resource every check depends on. If we cannot list
	// them, there is no audit — fail loudly instead of printing a perfect
	// score for an unreachable cluster.
	ns := opts.Namespace
	lo := metav1.ListOptions{}
	pods, err := cs.CoreV1().Pods(ns).List(ctx, lo)
	if err != nil {
		return nil, fmt.Errorf("cannot list pods (is the cluster reachable and are you authorised?): %w", err)
	}
	snap.Pods = pods.Items

	if v, err := cs.Discovery().ServerVersion(); err == nil && v != nil {
		snap.ServerVersion = v.GitVersion
	} else if err != nil {
		snap.warn("server version: %v", err)
	}

	// Everything else is best-effort: RBAC frequently forbids some types.
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
	if l, err := cs.NetworkingV1().NetworkPolicies(ns).List(ctx, lo); err == nil {
		snap.NetworkPolicies = l.Items
	} else {
		snap.warn("list networkpolicies: %v", err)
	}
	if l, err := cs.NetworkingV1().Ingresses(ns).List(ctx, lo); err == nil {
		snap.Ingresses = l.Items
	} else {
		snap.warn("list ingresses: %v", err)
	}

	snap.scrub()
	return snap, nil
}

// Empty reports whether the snapshot holds nothing to audit. A loaded file
// can be empty even though a live collection cannot.
func (s *Snapshot) Empty() bool {
	return len(s.Pods) == 0 && len(s.Nodes) == 0 && len(s.Deployments) == 0 &&
		len(s.StatefulSets) == 0 && len(s.DaemonSets) == 0
}

func (s *Snapshot) warn(format string, args ...any) {
	s.Warnings = append(s.Warnings, fmt.Sprintf(format, args...))
}

// scrub removes managedFields, last-applied annotations and node image lists.
// These can be hundreds of KB per object and never inform a check. It also
// drops container environment variables, which may carry inline secrets, so a
// saved snapshot is safe to share with a reviewer.
func (s *Snapshot) scrub() {
	clean := func(om *metav1.ObjectMeta) {
		om.ManagedFields = nil
		delete(om.Annotations, "kubectl.kubernetes.io/last-applied-configuration")
	}
	stripEnv := func(spec *corev1.PodSpec) {
		for i := range spec.Containers {
			spec.Containers[i].Env = nil
		}
		for i := range spec.InitContainers {
			spec.InitContainers[i].Env = nil
		}
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
		stripEnv(&s.Pods[i].Spec)
	}
	for i := range s.Deployments {
		clean(&s.Deployments[i].ObjectMeta)
		stripEnv(&s.Deployments[i].Spec.Template.Spec)
	}
	for i := range s.StatefulSets {
		clean(&s.StatefulSets[i].ObjectMeta)
		stripEnv(&s.StatefulSets[i].Spec.Template.Spec)
	}
	for i := range s.DaemonSets {
		clean(&s.DaemonSets[i].ObjectMeta)
		stripEnv(&s.DaemonSets[i].Spec.Template.Spec)
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
	for i := range s.NetworkPolicies {
		clean(&s.NetworkPolicies[i].ObjectMeta)
	}
	for i := range s.Ingresses {
		clean(&s.Ingresses[i].ObjectMeta)
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
