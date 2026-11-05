// kubepulse: a read-only Kubernetes cluster health, security and cost audit.
//
// Usage:
//
//	kubepulse                         # audit current kube-context, print Markdown
//	kubepulse --format json           # machine-readable output
//	kubepulse --save snap.json        # also persist the collected snapshot
//	kubepulse --load snap.json        # audit a snapshot offline (no cluster access)
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sereose/kubepulse/internal/checks"
	"github.com/sereose/kubepulse/internal/report"
	"github.com/sereose/kubepulse/internal/snapshot"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "kubepulse:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		kubeconfig  = flag.String("kubeconfig", "", "path to kubeconfig (default: $KUBECONFIG or ~/.kube/config)")
		kubeContext = flag.String("context", "", "kube-context to use (default: current)")
		namespace   = flag.String("namespace", "", "restrict audit to one namespace (default: all)")
		excludeNS   = flag.String("exclude-ns", "kube-system,kube-public,kube-node-lease", "comma-separated namespaces to ignore")
		format      = flag.String("format", "md", "output format: md | json")
		output      = flag.String("output", "", "write report to file instead of stdout")
		save        = flag.String("save", "", "save collected snapshot to this JSON file")
		load        = flag.String("load", "", "load snapshot from JSON file instead of querying a cluster")
		timeout     = flag.Duration("timeout", 60*time.Second, "cluster query timeout")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("kubepulse", version)
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
		fmt.Fprintf(os.Stderr, "snapshot saved to %s\n", *save)
	}

	excluded := splitCSV(*excludeNS)
	findings := checks.RunAll(snap, checks.Options{ExcludedNamespaces: excluded})
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
		fmt.Print(out)
		return nil
	}
	if err := os.WriteFile(*output, []byte(out), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "report written to %s (score %d/100)\n", *output, rep.Score)
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
