package checks

import (
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
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

func goodContainer() corev1.Container {
	return corev1.Container{
		Name:  "app",
		Image: "registry.example.com:5000/team/app:1.4.2",
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("128Mi")},
			Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")},
		},
		ReadinessProbe:  &corev1.Probe{},
		LivenessProbe:   &corev1.Probe{},
		SecurityContext: &corev1.SecurityContext{RunAsNonRoot: ptr(true)},
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
	d := deployment("prod", "api", 3, goodContainer())
	snap := &snapshot.Snapshot{
		Deployments: []appsv1.Deployment{d},
		PDBs: []policyv1.PodDisruptionBudget{{
			ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod"},
			Spec:       policyv1.PodDisruptionBudgetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}}},
		}},
	}
	fs := RunAll(snap, Options{})
	for _, f := range fs {
		if f.Category != Cost { // COST004 (no HPA) is expected for 3 pinned replicas
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
	// Sorted by severity desc: first must be the Critical one.
	if fs[0].Severity != Critical {
		t.Errorf("expected first finding Critical, got %s", fs[0].Severity)
	}
}

func TestExcludedNamespaceIsSkipped(t *testing.T) {
	d := deployment("kube-system", "coredns", 1, corev1.Container{Name: "c", Image: "coredns:latest"})
	snap := &snapshot.Snapshot{Deployments: []appsv1.Deployment{d}}
	if fs := RunAll(snap, Options{ExcludedNamespaces: []string{"kube-system"}}); len(fs) != 0 {
		t.Errorf("expected no findings for excluded namespace, got %d", len(fs))
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
	fs := findingsFor(RunAll(snap, Options{}), "COST001")
	// two orphans + one cluster-level total
	if len(fs) != 3 {
		t.Fatalf("expected 3 COST001 findings, got %d", len(fs))
	}
	for _, f := range fs {
		if f.Object == "PersistentVolumeClaim/used" {
			t.Errorf("used PVC should not be flagged")
		}
	}
}

func TestStuckPendingAndCrashLoop(t *testing.T) {
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
		},
	}
	fs := findingsFor(RunAll(snap, Options{}), "POD001")
	if len(fs) != 2 {
		t.Fatalf("expected 2 POD001 findings (stuck + crash), got %d: %+v", len(fs), fs)
	}
}

func TestNodeHeadroomOversized(t *testing.T) {
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
		Pods: []corev1.Pod{{
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2"), corev1.ResourceMemory: resource.MustParse("4Gi")},
			}}}},
		}},
	}
	fs := findingsFor(RunAll(snap, Options{}), "COST003")
	if len(fs) != 1 || fs[0].Severity != Medium {
		t.Fatalf("expected one Medium oversized finding, got %+v", fs)
	}
}
