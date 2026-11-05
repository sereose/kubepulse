// Package report turns findings into a score and human/machine-readable output.
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sereose/kubepulse/internal/checks"
	"github.com/sereose/kubepulse/internal/snapshot"
)

// Report is the full audit result.
type Report struct {
	Tool        string           `json:"tool"`
	Version     string           `json:"version"`
	GeneratedAt time.Time        `json:"generatedAt"`
	Cluster     Cluster          `json:"cluster"`
	Score       int              `json:"score"` // 0–100
	Grade       string           `json:"grade"` // A–F
	Summary     Summary          `json:"summary"`
	Findings    []checks.Finding `json:"findings"`
	Warnings    []string         `json:"warnings,omitempty"`
}

// Cluster is the inventory header.
type Cluster struct {
	Context      string `json:"context,omitempty"`
	Version      string `json:"version,omitempty"`
	Nodes        int    `json:"nodes"`
	Namespaces   int    `json:"namespaces"`
	Pods         int    `json:"pods"`
	Deployments  int    `json:"deployments"`
	StatefulSets int    `json:"statefulSets"`
	DaemonSets   int    `json:"daemonSets"`
	Services     int    `json:"services"`
	PVCs         int    `json:"pvcs"`
}

// Summary counts findings by severity and category.
type Summary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"bySeverity"`
	ByCategory map[string]int `json:"byCategory"`
}

// Build computes the score and assembles the report.
func Build(s *snapshot.Snapshot, findings []checks.Finding, version string) *Report {
	r := &Report{
		Tool:        "kubepulse",
		Version:     version,
		GeneratedAt: time.Now().UTC(),
		Cluster: Cluster{
			Context:      s.ContextName,
			Version:      s.ServerVersion,
			Nodes:        len(s.Nodes),
			Namespaces:   len(s.Namespaces),
			Pods:         len(s.Pods),
			Deployments:  len(s.Deployments),
			StatefulSets: len(s.StatefulSets),
			DaemonSets:   len(s.DaemonSets),
			Services:     len(s.Services),
			PVCs:         len(s.PVCs),
		},
		Findings: findings,
		Warnings: s.Warnings,
		Summary: Summary{
			Total:      len(findings),
			BySeverity: map[string]int{},
			ByCategory: map[string]int{},
		},
	}
	// Penalty is capped per check: one systemic gap (say, no runAsNonRoot on
	// 40 Deployments) should hurt, but not more than three times its weight.
	// Otherwise every real cluster scores F and the number stops meaning anything.
	perCheck := map[string]int{}
	perCheckCount := map[string]int{}
	for _, f := range findings {
		r.Summary.BySeverity[f.Severity.String()]++
		r.Summary.ByCategory[string(f.Category)]++
		if perCheckCount[f.CheckID] < maxPenalizedPerCheck {
			perCheck[f.CheckID] += f.Severity.Penalty()
			perCheckCount[f.CheckID]++
		}
	}
	penalty := 0
	for _, p := range perCheck {
		penalty += p
	}
	// Diminishing penalty: many Low findings should not drive a cluster to 0.
	r.Score = score(penalty)
	r.Grade = grade(r.Score)
	return r
}

// maxPenalizedPerCheck is how many findings of one check count toward the score.
const maxPenalizedPerCheck = 3

func score(penalty int) int {
	// Linear up to 40 points, then each extra point of penalty costs half.
	sc := 100
	if penalty <= 40 {
		sc -= penalty
	} else {
		sc -= 40 + (penalty-40)/2
	}
	if sc < 0 {
		sc = 0
	}
	return sc
}

func grade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

// JSON renders the report as indented JSON.
func (r *Report) JSON() (string, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b) + "\n", nil
}

// Markdown renders a report suitable for pasting into a doc or PR.
func (r *Report) Markdown() string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	w("# kubepulse audit report\n\n")
	w("**Score: %d/100 (grade %s)** · %d findings · generated %s\n\n",
		r.Score, r.Grade, r.Summary.Total, r.GeneratedAt.Format("2006-01-02 15:04 UTC"))

	w("## Cluster\n\n")
	w("| | |\n|---|---|\n")
	if r.Cluster.Context != "" {
		w("| Context | `%s` |\n", r.Cluster.Context)
	}
	if r.Cluster.Version != "" {
		w("| Kubernetes | %s |\n", r.Cluster.Version)
	}
	w("| Nodes | %d |\n| Namespaces | %d |\n| Pods | %d |\n", r.Cluster.Nodes, r.Cluster.Namespaces, r.Cluster.Pods)
	w("| Deployments / StatefulSets / DaemonSets | %d / %d / %d |\n", r.Cluster.Deployments, r.Cluster.StatefulSets, r.Cluster.DaemonSets)
	w("| Services / PVCs | %d / %d |\n\n", r.Cluster.Services, r.Cluster.PVCs)

	w("## Summary\n\n")
	w("| Severity | Count |\n|---|---|\n")
	for _, sev := range []checks.Severity{checks.Critical, checks.High, checks.Medium, checks.Low} {
		w("| %s | %d |\n", sev, r.Summary.BySeverity[sev.String()])
	}
	w("\n| Category | Count |\n|---|---|\n")
	for _, cat := range sortedKeys(r.Summary.ByCategory) {
		w("| %s | %d |\n", cat, r.Summary.ByCategory[cat])
	}
	w("\n")

	if len(r.Findings) == 0 {
		w("## Findings\n\nNo findings. Either the cluster is in great shape or RBAC hid most resources — check Warnings.\n\n")
	} else {
		w("## Top priorities\n\n")
		for i, f := range r.Findings {
			if i == 5 || f.Severity < checks.High {
				break
			}
			w("%d. **[%s] %s** — %s%s\n", i+1, f.Severity, f.Title, loc(f), f.Message)
		}
		w("\n## Findings by check\n\n")
		for _, grp := range groupByCheck(r.Findings) {
			w("### %s · %s (%d)\n\n", grp.ID, grp.Title, len(grp.Items))
			w("*%s*\n\n", grp.Items[0].Remediation)
			w("| Severity | Namespace | Object | Detail |\n|---|---|---|---|\n")
			for _, f := range grp.Items {
				w("| %s | %s | `%s` | %s |\n", f.Severity, orDash(f.Namespace), f.Object, escapePipes(f.Message))
			}
			w("\n")
		}
	}

	if len(r.Warnings) > 0 {
		w("## Warnings\n\n")
		for _, wn := range r.Warnings {
			w("- %s\n", wn)
		}
		w("\n")
	}

	w("---\n*Read-only audit. Score weights Critical=15, High=8, Medium=3, Low=1; at most %d findings per check count, with diminishing penalties after 40 points. ", maxPenalizedPerCheck)
	w("Findings are heuristics: review each against your context before acting.*\n")
	return b.String()
}

type group struct {
	ID, Title string
	Items     []checks.Finding
}

// groupByCheck preserves severity order of first appearance.
func groupByCheck(fs []checks.Finding) []group {
	idx := map[string]int{}
	var out []group
	for _, f := range fs {
		i, ok := idx[f.CheckID]
		if !ok {
			idx[f.CheckID] = len(out)
			out = append(out, group{ID: f.CheckID, Title: f.Title})
			i = len(out) - 1
		}
		out[i].Items = append(out[i].Items, f)
	}
	return out
}

func loc(f checks.Finding) string {
	if f.Object == "" {
		return ""
	}
	if f.Namespace == "" {
		return "`" + f.Object + "`: "
	}
	return "`" + f.Namespace + "/" + f.Object + "`: "
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func escapePipes(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
