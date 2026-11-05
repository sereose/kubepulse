package snapshot

import (
	"context"
	"path/filepath"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCollectFromFakeClientset(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "p1", Namespace: "prod",
				Annotations:   map[string]string{"kubectl.kubernetes.io/last-applied-configuration": "{...}", "keep": "me"},
				ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kubectl"}},
			},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{
				Name: "c", Image: "app:1",
				Env: []corev1.EnvVar{{Name: "DB_PASSWORD", Value: "hunter2"}},
			}}},
		},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "d1", Namespace: "prod"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "d2", Namespace: "other"}},
	)

	snap, err := CollectFrom(context.Background(), cs, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Namespaces) != 1 || len(snap.Nodes) != 1 || len(snap.Pods) != 1 || len(snap.Deployments) != 2 {
		t.Fatalf("unexpected counts: ns=%d nodes=%d pods=%d deps=%d",
			len(snap.Namespaces), len(snap.Nodes), len(snap.Pods), len(snap.Deployments))
	}

	p := snap.Pods[0]
	if p.ManagedFields != nil {
		t.Error("managedFields not scrubbed")
	}
	if _, ok := p.Annotations["kubectl.kubernetes.io/last-applied-configuration"]; ok {
		t.Error("last-applied annotation not scrubbed")
	}
	if p.Annotations["keep"] != "me" {
		t.Error("unrelated annotation was removed")
	}
	if p.Spec.Containers[0].Env != nil {
		t.Error("container env (potential secrets) not scrubbed")
	}

	// Namespace filter.
	snap, err = CollectFrom(context.Background(), cs, Options{Namespace: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Deployments) != 1 || snap.Deployments[0].Name != "d1" {
		t.Errorf("namespace filter failed: %+v", snap.Deployments)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "a"}},
	)
	snap, err := CollectFrom(context.Background(), cs, Options{})
	if err != nil {
		t.Fatal(err)
	}
	snap.ContextName = "ctx"
	snap.Warnings = []string{"w1"}

	path := filepath.Join(t.TempDir(), "snap.json")
	if err := snap.SaveFile(path); err != nil {
		t.Fatal(err)
	}
	got, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.ContextName != "ctx" || len(got.Nodes) != 1 || len(got.Pods) != 1 || len(got.Warnings) != 1 {
		t.Errorf("round trip lost data: %+v", got)
	}
	if !got.CollectedAt.Equal(snap.CollectedAt) {
		t.Errorf("collectedAt changed: %v vs %v", got.CollectedAt, snap.CollectedAt)
	}
}

func TestLoadFileBadJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := writeFile(path, "{not json"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Error("expected parse error")
	}
}
