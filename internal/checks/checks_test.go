package checks

import (
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/sereose/kubepulse/internal/snapshot"
)

func ptr[T any](v T) *T { return &v }

func deployment(ns, name string, replicas int32, c corev1.Container) appsv1.Deployment {
	labels := map[string]string{"app": name}
	return appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr(replicas),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{c}},
			},
		},
	}
}

// hardened returns a Deployment that should produce zero findings except COST004.
func hardened(ns, name string, replicas int32) appsv1.Deployment {
	d := deployment(ns, name, replicas, goodContainer())
	d.Spec.Template.Spec.ServiceAccountName = "app-sa"
	d.Spec.Template.Spec.AutomountServiceAccountToken = ptr(false)
	d.Spec.Template.Spec.TopologySpreadConstraints = []corev1.TopologySpreadConstraint{{TopologyKey: "kubernetes.io/hostname"}}
	return d
}

func goodContainer() corev1.Container {
	return corev1.Container{
		Name:  "app",
		Image: "registry.example.com:5000/team/app:1.4.2",
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("128Mi")},
			Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")},
		},
		ReadinessProbe: &corev1.Probe{},
		LivenessProbe:  &corev1.Probe{},
		SecurityContext: &corev1.SecurityContext{
			RunAsNonRoot:             ptr(true),
			AllowPrivilegeEscalation: ptr(false),
			ReadOnlyRootFilesystem:   ptr(true),
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		},
	}
}

func findingsFor(fs []Finding, id string) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.CheckID == id {
			out = append(out, f)
		}
	}
	return out
}

func TestCleanWorkloadProducesNoWorkloadFindings(t *testing.T) {
	snap := &snapshot.Snapshot{
		Nodes:       []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "a"}}, {ObjectMeta: metav1.ObjectMeta{Name: "b"}}},
		Deployments: []appsv1.Deployment{hardened("prod", "api", 3)},
		PDBs: []policyv1.PodDisruptionBudget{{
			ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod"},
			Spec:       policyv1.PodDisruptionBudgetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}}},
		}},
	}
	fs := RunAll(snap, Options{})
	for _, f := range fs {
		if f.CheckID != "COST004" { // 3 pinned replicas without HPA is expected
			t.Errorf("unexpected finding %s: %s", f.CheckID, f.Message)
		}
	}
	if got := findingsFor(fs, "COST004"); len(got) != 1 {
		t.Errorf("expected 1 COST004 finding, got %d", len(got))
	}
}

func TestBadWorkloadFlagsEverything(t *testing.T) {
	c := corev1.Container{
		Name:            "web",
		Image:           "nginx",
		SecurityContext: &corev1.SecurityContext{Privileged: ptr(true)},
	}
	d := deployment("default", "web", 1, c)
	d.Spec.Template.Spec.HostNetwork = true
	snap := &snapshot.Snapshot{Deployments: []appsv1.Deployment{d}}

	fs := RunAll(snap, Options{})
	want := map[string]Severity{
		"WL001":  High,     // no requests/limits at all
		"WL002":  Medium,   // single replica
		"WL003":  Medium,   // no probes
		"WL004":  Medium,   // untagged image
		"SEC001": Critical, // privileged
		"SEC002": High,     // root allowed
		"SEC003": High,     // hostNetwork
		"SEC004": Medium,   // default SA token
		"SEC006": Low,      // hardening
	}
	for id, sev := range want {
		got := findingsFor(fs, id)
		if len(got) == 0 {
			t.Errorf("expected finding %s", id)
			continue
		}
		if got[0].Severity != sev {
			t.Errorf("%s: want severity %s, got %s", id, sev, got[0].Severity)
		}
	}
	if fs[0].Severity != Critical {
		t.Errorf("expected first finding Critical, got %s", fs[0].Severity)
	}
}

func TestExcludedNamespaceIsSkipped(t *testing.T) {
	d := deployment("kube-system", "coredns", 1, corev1.Container{Name: "c", Image: "coredns:latest"})
	snap := &snapshot.Snapshot{
		Deployments: []appsv1.Deployment{d},
		Pods:        []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "kube-system"}}},
	}
	if fs := RunAll(snap, Options{ExcludedNamespaces: []string{"kube-system"}}); len(fs) != 0 {
		t.Errorf("expected no findings for excluded namespace, got %d: %+v", len(fs), fs)
	}
}

func TestIsMutableTag(t *testing.T) {
	cases := map[string]bool{
		"nginx":                                 true,
		"nginx:latest":                          true,
		"nginx:1.25":                            false,
		"registry.io:5000/app":                  true,
		"registry.io:5000/app:latest":           true,
		"registry.io:5000/app:v2":               false,
		"ghcr.io/org/app@sha256:" + sha256Zeros: false,
	}
	for img, want := range cases {
		if got := isMutableTag(img); got != want {
			t.Errorf("isMutableTag(%q) = %v, want %v", img, got, want)
		}
	}
}

const sha256Zeros = "0000000000000000000000000000000000000000000000000000000000000000"

func TestOrphanPVCAndUsedPVC(t *testing.T) {
	pvc := func(name string) corev1.PersistentVolumeClaim {
		return corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "data"},
			Spec: corev1.PersistentVolumeClaimSpec{Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("100Gi")},
			}},
			Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
		}
	}
	snap := &snapshot.Snapshot{
		PVCs: []corev1.PersistentVolumeClaim{pvc("used"), pvc("orphan-a"), pvc("orphan-b")},
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "db-0", Namespace: "data"},
			Spec: corev1.PodSpec{Volumes: []corev1.Volume{{
				Name:         "data",
				VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "used"}},
			}}},
		}},
	}
	fs := findingsFor(RunAll(snap, Options{StorageMonthlyCostPerGi: 0.10}), "COST001")
	if len(fs) != 3 { // two orphans + one cluster-level total
		t.Fatalf("expected 3 COST001 findings, got %d", len(fs))
	}
	var total *Finding
	for i := range fs {
		if fs[i].Object == "PersistentVolumeClaim/used" {
			t.Errorf("used PVC should not be flagged")
		}
		if fs[i].Object == "cluster" {
			total = &fs[i]
		}
	}
	if total == nil || !contains(total.Message, "~$20/month") {
		t.Errorf("expected priced total, got %+v", total)
	}
}

func TestPodHealthChecksAreSeparate(t *testing.T) {
	now := time.Now()
	snap := &snapshot.Snapshot{
		CollectedAt: now,
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "stuck", Namespace: "app", CreationTimestamp: metav1.NewTime(now.Add(-time.Hour))},
				Status:     corev1.PodStatus{Phase: corev1.PodPending},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "fresh", Namespace: "app", CreationTimestamp: metav1.NewTime(now.Add(-time.Minute))},
				Status:     corev1.PodStatus{Phase: corev1.PodPending},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "crash", Namespace: "app"},
				Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
					Name: "c", RestartCount: 42,
					State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
				}}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "oom", Namespace: "app"},
				Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
					Name: "c", RestartCount: 12,
					State:                corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
					LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled"}},
				}}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "flappy", Namespace: "app"},
				Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
					Name: "c", RestartCount: 15,
					State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
				}}},
			},
		},
	}
	fs := RunAll(snap, Options{})
	expect := map[string]string{"POD001": "stuck", "POD002": "crash", "POD003": "oom", "POD004": "flappy"}
	for id, pod := range expect {
		got := findingsFor(fs, id)
		if len(got) != 1 || got[0].Object != "Pod/"+pod {
			t.Errorf("%s: want exactly Pod/%s, got %+v", id, pod, got)
		}
	}
	if msg := findingsFor(fs, "POD001")[0].Message; !contains(msg, "Pending for 1h0m:") {
		t.Errorf("duration format: %q", msg)
	}
}

func TestOOMCrashLoopReportedOnce(t *testing.T) {
	snap := &snapshot.Snapshot{Pods: []corev1.Pod{{
		ObjectMeta: metav1.ObjectMeta{Name: "leaky", Namespace: "app"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
			Name: "hog", RestartCount: 15,
			State:                corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
			LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled"}},
		}}},
	}}}
	fs := RunAll(snap, Options{})
	if len(findingsFor(fs, "POD002")) != 0 {
		t.Error("OOM-driven crash loop must not also be a POD002 finding")
	}
	oom := findingsFor(fs, "POD003")
	if len(oom) != 1 || !contains(oom[0].Message, "CrashLoopBackOff") {
		t.Errorf("POD003 should mention the crash loop: %+v", oom)
	}
}

func TestHumanDuration(t *testing.T) {
	cases := map[time.Duration]string{
		55 * time.Minute:             "55m",
		3*time.Hour + 20*time.Minute: "3h20m",
		52*time.Hour + 4*time.Minute: "2d4h",
		34*time.Hour + 0*time.Minute: "1d10h",
	}
	for d, want := range cases {
		if got := humanDuration(d); got != want {
			t.Errorf("humanDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestNodeHeadroomOversizedWithCost(t *testing.T) {
	node := func(name string) corev1.Node {
		return corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Status: corev1.NodeStatus{Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("8"),
				corev1.ResourceMemory: resource.MustParse("32Gi"),
			}},
		}
	}
	snap := &snapshot.Snapshot{
		Nodes: []corev1.Node{node("a"), node("b"), node("c")},
		Pods: []corev1.Pod{
			{
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
				Spec: corev1.PodSpec{NodeName: "a", Containers: []corev1.Container{{Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("6"), corev1.ResourceMemory: resource.MustParse("4Gi")},
				}}}},
			},
			// Unschedulable monster: must NOT be counted (no NodeName).
			{
				Status: corev1.PodStatus{Phase: corev1.PodPending},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("64"), corev1.ResourceMemory: resource.MustParse("512Gi")},
				}}}},
			},
		},
	}
	// cpu 6/24 = 25%, mem 4/96 ≈ 4% → oversized; idle = 75% × 3 nodes × $200 = $450
	fs := findingsFor(RunAll(snap, Options{NodeMonthlyCost: 200}), "COST003")
	if len(fs) != 1 || fs[0].Severity != Medium {
		t.Fatalf("expected one Medium oversized finding, got %+v", fs)
	}
	if !contains(fs[0].Message, "~$450/month") || !contains(fs[0].Message, "6 cores / 24 cores") {
		t.Errorf("unexpected message: %q", fs[0].Message)
	}
}

func TestOrphanPVCPendingIsHygieneNotCost(t *testing.T) {
	snap := &snapshot.Snapshot{PVCs: []corev1.PersistentVolumeClaim{{
		ObjectMeta: metav1.ObjectMeta{Name: "waiting", Namespace: "a"},
		Spec: corev1.PersistentVolumeClaimSpec{Resources: corev1.VolumeResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Gi")},
		}},
		Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending},
	}}}
	fs := findingsFor(RunAll(snap, Options{}), "COST001")
	if len(fs) != 1 || fs[0].Severity != Low || fs[0].Category != Hygiene || contains(fs[0].Message, "bound") {
		t.Errorf("pending PVC should be a Low hygiene finding, got %+v", fs)
	}
}

func TestNetworkPolicyCoverageAndIngressTLS(t *testing.T) {
	snap := &snapshot.Snapshot{
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "open"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "locked"}},
		},
		NetworkPolicies: []networkingv1.NetworkPolicy{{ObjectMeta: metav1.ObjectMeta{Name: "deny", Namespace: "locked"}}},
		Ingresses: []networkingv1.Ingress{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "plain", Namespace: "open"},
				Spec:       networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{Host: "app.example.com"}}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "secure", Namespace: "open"},
				Spec: networkingv1.IngressSpec{
					TLS:   []networkingv1.IngressTLS{{Hosts: []string{"api.example.com"}}},
					Rules: []networkingv1.IngressRule{{Host: "api.example.com"}},
				},
			},
		},
	}
	fs := RunAll(snap, Options{})
	np := findingsFor(fs, "NS002")
	if len(np) != 1 || np[0].Namespace != "open" {
		t.Errorf("NS002: want only namespace 'open', got %+v", np)
	}
	tls := findingsFor(fs, "SEC005")
	if len(tls) != 1 || tls[0].Object != "Ingress/plain" {
		t.Errorf("SEC005: want only Ingress/plain, got %+v", tls)
	}
}

func TestAntiAffinityNeedsTwoNodes(t *testing.T) {
	d := deployment("prod", "api", 2, goodContainer())
	one := &snapshot.Snapshot{Nodes: []corev1.Node{{}}, Deployments: []appsv1.Deployment{d}}
	if fs := findingsFor(RunAll(one, Options{}), "WL006"); len(fs) != 0 {
		t.Errorf("single-node cluster should not flag WL006")
	}
	two := &snapshot.Snapshot{Nodes: []corev1.Node{{}, {}}, Deployments: []appsv1.Deployment{d}}
	if fs := findingsFor(RunAll(two, Options{}), "WL006"); len(fs) != 1 {
		t.Errorf("expected WL006 on two-node cluster, got %d", len(fs))
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
