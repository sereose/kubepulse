package report

import (
	"strings"
	"testing"

	"github.com/sereose/kubepulse/internal/checks"
	"github.com/sereose/kubepulse/internal/snapshot"
)

func TestScoreAndGrade(t *testing.T) {
	cases := []struct {
		penalty, wantScore int
		wantGrade          string
	}{
		{0, 100, "A"},
		{10, 90, "A"},
		{25, 75, "B"},
		{40, 60, "C"},
		{80, 40, "D"},
		{200, 0, "F"},
	}
	for _, c := range cases {
		if got := score(c.penalty); got != c.wantScore {
			t.Errorf("score(%d) = %d, want %d", c.penalty, got, c.wantScore)
		}
		if got := grade(c.wantScore); got != c.wantGrade {
			t.Errorf("grade(%d) = %s, want %s", c.wantScore, got, c.wantGrade)
		}
	}
}

func TestPerCheckPenaltyCap(t *testing.T) {
	var fs []checks.Finding
	for i := 0; i < 40; i++ {
		fs = append(fs, checks.Finding{CheckID: "SEC002", Severity: checks.High, Category: checks.Security})
	}
	r := Build(&snapshot.Snapshot{}, fs, "test")
	// 40 × High would be 320 penalty → 0. Capped at 3 × 8 = 24 → 76.
	if r.Score != 76 {
		t.Errorf("score = %d, want 76 (per-check cap)", r.Score)
	}
	if r.Summary.Total != 40 || r.Summary.BySeverity["HIGH"] != 40 {
		t.Errorf("summary must still count every finding: %+v", r.Summary)
	}
}

func TestMarkdownContainsEssentials(t *testing.T) {
	snap := &snapshot.Snapshot{ServerVersion: "v1.31.0", ContextName: "test"}
	fs := []checks.Finding{
		{CheckID: "SEC001", Title: "Privileged containers", Severity: checks.Critical, Category: checks.Security,
			Namespace: "prod", Object: "Deployment/web", Message: "runs privileged | really", Remediation: "drop it"},
		{CheckID: "COST003", Title: "Capacity", Severity: checks.Low, Category: checks.Cost,
			Object: "cluster", Message: "fine", Remediation: "compare"},
	}
	r := Build(snap, fs, "test")
	if r.Score != 100-15-1 {
		t.Errorf("score = %d", r.Score)
	}
	md := r.Markdown()
	for _, want := range []string{"Score: 84/100", "grade B", "## Top priorities", "SEC001", "\\|", "v1.31.0"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	js, err := r.JSON()
	if err != nil || !strings.Contains(js, `"severity": "CRITICAL"`) {
		t.Errorf("json missing severity name: %v\n%s", err, js)
	}
}
