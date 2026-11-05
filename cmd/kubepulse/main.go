// kubepulse: a read-only Kubernetes cluster health, security and cost audit.
//
// Usage:
//
//	kubepulse                         # audit current kube-context, print Markdown
//	kubepulse --format json           # machine-readable output
//	kubepulse --save snap.json        # also persist the collected snapshot
//	kubepulse --load snap.json        # audit a snapshot offline (no cluster access)
//	kubepulse --fail-below 70         # exit 2 if score < 70 (CI gate)
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sereose/kubepulse/internal/checks"
	"github.com/sereose/kubepulse/internal/report"
	"github.com/sereose/kubepulse/internal/snapshot"
)

// Set by goreleaser via -ldflags.
var (
	version = "dev"
	commit  = ""
	date    = ""
)

// errScoreBelowThreshold is returned when --fail-below is not met.
var errScoreBelowThreshold = errors.New("score below threshold")

func main() {
	err := run(os.Args[1:], os.Stdout, os.Stderr)
	switch {
	case err == nil:
	case errors.Is(err, errScoreBelowThreshold):
		os.Exit(2)
	default:
		fmt.Fprintln(os.Stderr, "kubepulse:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr *os.File) error {
	fs := flag.NewFlagSet("kubepulse", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		kubeconfig  = fs.String("kubeconfig", "", "path to kubeconfig (default: $KUBECONFIG or ~/.kube/config)")
		kubeContext = fs.String("context", "", "kube-context to use (default: current)")
		namespace   = fs.String("namespace", "", "restrict audit to one namespace (default: all)")
		excludeNS   = fs.String("exclude-ns", "kube-system,kube-public,kube-node-lease", "comma-separated namespaces to ignore")
		format      = fs.String("format", "md", "output format: md | json")
		output      = fs.String("output", "", "write report to file instead of stdout")
		save        = fs.String("save", "", "save collected snapshot to this JSON file")
		load        = fs.String("load", "", "load snapshot from JSON file instead of querying a cluster")
		timeout     = fs.Duration("timeout", 60*time.Second, "cluster query timeout")
		failBelow   = fs.Int("fail-below", 0, "exit with code 2 if score is below this value (0 = disabled)")
		nodeCost    = fs.Float64("node-monthly-cost", 0, "average $/node/month; enables $ estimates for idle capacity")
		storageCost = fs.Float64("storage-cost-per-gi", 0, "$/Gi/month for persistent volumes; prices orphan PVCs (e.g. 0.10 for gp3)")
		pendingSec  = fs.Int("pending-threshold", 600, "seconds before a Pending pod counts as stuck")
		showVersion = fs.Bool("version", false, "print version and exit")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *showVersion {
		v := version
		if commit != "" {
			v += " (" + commit
			if date != "" {
				v += ", " + date
			}
			v += ")"
		}
		fmt.Fprintln(stdout, "kubepulse", v)
		return nil
	}

	var snap *snapshot.Snapshot
	var err error

	if *load != "" {
		snap, err = snapshot.LoadFile(*load)
		if err != nil {
			return fmt.Errorf("load snapshot: %w", err)
		}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()
		snap, err = snapshot.Collect(ctx, snapshot.Options{
			Kubeconfig: *kubeconfig,
			Context:    *kubeContext,
			Namespace:  *namespace,
		})
		if err != nil {
			return fmt.Errorf("collect: %w", err)
		}
	}

	if *save != "" {
		if err := snap.SaveFile(*save); err != nil {
			return fmt.Errorf("save snapshot: %w", err)
		}
		fmt.Fprintf(stderr, "snapshot saved to %s\n", *save)
	}

	findings := checks.RunAll(snap, checks.Options{
		ExcludedNamespaces:      splitCSV(*excludeNS),
		PendingThresholdSeconds: *pendingSec,
		NodeMonthlyCost:         *nodeCost,
		StorageMonthlyCostPerGi: *storageCost,
	})
	rep := report.Build(snap, findings, version)

	var out string
	switch strings.ToLower(*format) {
	case "md", "markdown":
		out = rep.Markdown()
	case "json":
		out, err = rep.JSON()
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown format %q (use md or json)", *format)
	}

	if *output == "" {
		fmt.Fprint(stdout, out)
	} else {
		if err := os.WriteFile(*output, []byte(out), 0o644); err != nil {
			return err
		}
		fmt.Fprintf(stderr, "report written to %s (score %d/100, grade %s)\n", *output, rep.Score, rep.Grade)
	}

	if *failBelow > 0 && rep.Score < *failBelow {
		fmt.Fprintf(stderr, "score %d is below threshold %d\n", rep.Score, *failBelow)
		return errScoreBelowThreshold
	}
	return nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
