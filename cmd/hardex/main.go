// Command hardex assesses Kubernetes manifests and cluster exports against
// security baselines.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/ManintheiCloud/Hardex/core/node"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ManintheiCloud/Hardex"
	"github.com/ManintheiCloud/Hardex/baselines"
	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/cluster"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/history"
	"github.com/ManintheiCloud/Hardex/core/modules"
	"github.com/ManintheiCloud/Hardex/core/verification"
	"github.com/ManintheiCloud/Hardex/integrations/reporting"
	"github.com/ManintheiCloud/Hardex/internal/durable"
	"github.com/ManintheiCloud/Hardex/kubernetes"
)

// Exit codes. They are part of the CLI contract and documented in README.
const (
	exitOK         = 0
	exitFindings   = 1 // findings at or above --fail-on, or a regression in diff
	exitUsage      = 2 // invalid arguments, configuration or input
	exitIncomplete = 3 // one or more rules failed; results understate risk
)

const usage = `Hardex — Kubernetes security assessment

Usage:
  hardex scan [flags] PATH...      Assess manifests, directories or "-" (stdin)
  hardex scan --cluster [flags]    Assess the live cluster (read-only)
  hardex scan --node [flags]       Assess this node's kubelet and static pod files
  hardex monitor [flags] PATH...|--cluster
                                   Assess repeatedly; record history; alert on drift
  hardex images [flags] PATH...|--cluster
                                   Resolve image digests; verify signatures (cosign
                                   key or keyless); look up SBOM vulnerabilities
  hardex verify-blob --bundle B --certificate-identity(-regexp) I
                     --certificate-oidc-issuer O FILE
                                   Verify a file's Sigstore keyless signature offline
  hardex fleet --contexts a,b,c    Assess several clusters and compare them
  hardex compare REPORT...         Compare saved reports across clusters
  hardex report REPORT.json        Evidence report (HTML/Markdown) and posture score
  hardex admission [flags]         Serve a validating admission webhook (enforce/warn/audit)
  hardex admission --preflight --cluster
                                   List existing objects enforce mode would reject
  hardex history DIR               Show trends from scan --history / monitor
  hardex rules [RULE-ID]           List rules, or explain one
  hardex profiles                  List built-in profiles
  hardex diff BEFORE AFTER         Compare two JSON reports (verify remediation)
  hardex fix [flags] PATH...       Plan fixes (dry run); --out writes patched manifests
  hardex fix --cluster --rules ... --apply
                                   Apply selected fixes with backup and verification
  hardex rollback BACKUP --cluster Undo an applied fix from its backup file
  hardex version                   Print version

Run "hardex <command> -h" for command flags.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "scan":
		return cmdScan(args[1:], stdin, stdout, stderr)
	case "rules":
		return cmdRules(args[1:], stdout, stderr)
	case "profiles":
		return cmdProfiles(stdout, stderr)
	case "diff":
		return cmdDiff(args[1:], stdout, stderr)
	case "images":
		return cmdImages(args[1:], stdin, stdout, stderr)
	case "verify-blob":
		return cmdVerifyBlob(args[1:], stdout, stderr)
	case "compare":
		return cmdCompare(args[1:], stdout, stderr)
	case "fleet":
		return cmdFleet(args[1:], stdout, stderr)
	case "report":
		return cmdReport(args[1:], stdout, stderr)
	case "admission":
		return cmdAdmission(args[1:], stdout, stderr)
	case "monitor":
		return cmdMonitor(args[1:], stdin, stdout, stderr)
	case "history":
		return cmdHistory(args[1:], stdout, stderr)
	case "fix":
		return cmdFix(args[1:], stdin, stdout, stderr)
	case "rollback":
		return cmdRollback(args[1:], stdin, stdout, stderr)
	case "version", "--version":
		fmt.Fprintf(stdout, "hardex %s\n", hardex.Version)
		return exitOK
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return exitOK
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
	return exitUsage
}

// parseInterleaved parses flags that may appear before or after positional
// arguments ("hardex scan ./k8s --format json"), which the standard flag
// package alone does not allow. "--" ends flag parsing; "-" is positional.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		if len(args) > len(rest) && args[len(args)-len(rest)-1] == "--" {
			return append(positional, rest...), nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func cmdScan(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var files multiFlag
	fs.Var(&files, "f", "file, directory or - (repeatable; positional arguments also accepted)")
	profile := fs.String("profile", "", "profile: "+strings.Join(baselines.ProfileNames(), ", ")+", or a path to a profile YAML (default from config, else baseline)")
	configPath := fs.String("config", "", "policy configuration file (never loaded implicitly)")
	format := fs.String("format", "text", "output format: "+strings.Join(reporting.Formats, ", "))
	output := fs.String("o", "", "write report to this file instead of stdout")
	failOn := fs.String("fail-on", "high", "exit 1 if any active finding is at or above this severity (info..critical, or none)")
	includeSystem := fs.Bool("include-system", false, "also assess Kubernetes-managed objects (RBAC matching a Kubernetes or kubeadm default, kube-system workloads and networking)")
	var mods multiFlag
	fs.Var(&mods, "module", "declarative rule module file (repeatable; never loaded implicitly)")
	var cloudIAM multiFlag
	fs.Var(&cloudIAM, "cloud-iam", "cloud IAM export (aws iam get-account-authorization-details, gcloud projects get-iam-policy, az role assignment list; JSON; repeatable) to rate workload cloud identities")
	historyDir := fs.String("history", "", "also record the report in this history directory (see hardex history)")
	keep := fs.Int("keep", 0, "with --history, keep only the newest N reports (0 = keep all)")
	stats := fs.Bool("stats", false, "print load and per-rule evaluation timings to stderr")
	nodeScan := fs.Bool("node", false, "assess this node's kubelet configuration (file and flag overrides) and static pod manifests, read from the local filesystem")
	nodeRoot := fs.String("node-root", "", "with --node, prefix for host paths (e.g. /host when the node's filesystem is mounted into a container)")
	nodeName := fs.String("node-name", "", "with --node, the node's name in findings (default $NODE_NAME, else the hostname)")
	kubeletConfig := fs.String("kubelet-config", "", "with --node, path of the kubelet configuration file on the node (default: discovered)")
	every := fs.Duration("every", 0, "with --node, rescan at this interval and write each report (for the node DaemonSet); runs until stopped")
	var cf clusterFlags
	cf.register(fs)
	positional, err := parseInterleaved(fs, args)
	if err != nil {
		return exitUsage
	}
	paths := append([]string(files), positional...)
	switch {
	case len(paths) == 0 && !cf.active() && !*nodeScan:
		fmt.Fprintln(stderr, "scan: no input; pass files, directories, - for stdin, --cluster or --node")
		return exitUsage
	case len(paths) > 0 && (cf.active() || *nodeScan), cf.active() && *nodeScan:
		fmt.Fprintln(stderr, "scan: pass one of paths, --cluster or --node")
		return exitUsage
	}
	if *every > 0 {
		if !*nodeScan || *output != "" || *every < time.Minute {
			fmt.Fprintln(stderr, "scan: --every needs --node, no -o, and an interval of at least 1m")
			return exitUsage
		}
		once := withoutFlag(args, "every")
		for {
			cmdScan(once, stdin, stdout, stderr)
			time.Sleep(*every)
		}
	}
	threshold, err := finding.ParseSeverity(*failOn)
	if err != nil {
		fmt.Fprintln(stderr, "scan:", err)
		return exitUsage
	}

	cfg, err := loadConfig(*configPath, *includeSystem)
	if err != nil {
		fmt.Fprintln(stderr, "scan:", err)
		return exitUsage
	}

	opts := hardex.ScanOptions{Paths: paths, Stdin: stdin, Config: cfg, Profile: *profile, Modules: mods, CloudIAM: cloudIAM}
	if *stats {
		opts.Stats = &hardex.Stats{}
	}
	if *nodeScan {
		res, err := node.Collect(node.Options{Root: *nodeRoot, NodeName: *nodeName, KubeletConfig: *kubeletConfig})
		if err != nil {
			fmt.Fprintln(stderr, "scan:", err)
			return exitUsage
		}
		for _, n := range res.Notes {
			fmt.Fprintln(stderr, "node:", n)
		}
		opts.Inventory, opts.CollectionErrors = res.Inventory, res.Errors
	}
	if cf.active() {
		client, err := cf.connect(cluster.ReadOnly)
		if err != nil {
			fmt.Fprintln(stderr, "scan:", err)
			return exitUsage
		}
		col, errs, warns, err := cf.collect(context.Background(), client)
		if err != nil {
			fmt.Fprintln(stderr, "scan:", err)
			return exitUsage
		}
		opts.Inventory, opts.CollectionErrors, opts.CollectionWarnings = col.Inventory, errs, warns
	}
	report, rules, err := hardex.Scan(opts)
	if err != nil {
		fmt.Fprintln(stderr, "scan:", err)
		return exitUsage
	}
	if opts.Stats != nil {
		printStats(stderr, opts.Stats)
	}

	if err := writeOutput(*output, stdout, func(w io.Writer) error { return reporting.Write(w, *format, report, rules) }); err != nil {
		fmt.Fprintln(stderr, "scan:", err)
		return exitUsage
	}
	if *output != "" {
		fmt.Fprintf(stderr, "report written to %s: %d findings (%d critical, %d high)\n",
			*output, report.Summary.Total, report.Summary.Critical, report.Summary.High)
	}
	if *historyDir != "" {
		store, err := history.Open(*historyDir)
		if err == nil {
			var path string
			if path, err = store.Save(report); err == nil {
				fmt.Fprintf(stderr, "recorded in history: %s\n", path)
				_, err = store.Prune(*keep)
			}
		}
		if err != nil {
			fmt.Fprintln(stderr, "scan: history:", err)
			return exitUsage
		}
	}

	switch {
	case !report.Complete():
		fmt.Fprintf(stderr, "scan: assessment incomplete: %s\n", strings.Join(report.Errors, "; "))
		return exitIncomplete
	case report.HighestSeverity() >= threshold:
		return exitFindings
	}
	return exitOK
}

func cmdRules(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var mods multiFlag
	fs.Var(&mods, "module", "also list rules from this module file (repeatable)")
	args, err := parseInterleaved(fs, args)
	if err != nil {
		return exitUsage
	}
	var extra []assessment.Rule
	for _, m := range mods {
		rules, err := modules.Load(m)
		if err != nil {
			fmt.Fprintln(stderr, "rules:", err)
			return exitUsage
		}
		extra = append(extra, rules...)
	}
	reg, err := kubernetes.Registry(extra...)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	if len(args) > 0 {
		rule, ok := reg.Get(args[0])
		if !ok {
			fmt.Fprintf(stderr, "unknown rule %q\n", args[0])
			return exitUsage
		}
		m := rule.Metadata()
		var profiles []string
		for _, name := range baselines.ProfileNames() {
			p, _ := baselines.Profile(name)
			for _, id := range p.Rules {
				if id == m.ID {
					profiles = append(profiles, name)
				}
			}
		}
		fmt.Fprintf(stdout, "%s  %s\n\nSeverity:  %s\nCategory:  %s\nProfiles:  %s\n\nWhat:  %s\n\nWhy:   %s\n\nFix:   %s\n",
			m.ID, m.Title, m.Severity, m.Category, strings.Join(profiles, ", "), m.Description, m.Rationale, m.Remediation)
		if m.Limitations != "" {
			fmt.Fprintf(stdout, "\nLimitations: %s\n", m.Limitations)
		}
		if len(m.References) > 0 {
			fmt.Fprintln(stdout, "\nReferences:")
			for _, r := range m.References {
				line := "  - " + r.Framework + ": " + r.Control
				if r.URL != "" {
					line += " <" + r.URL + ">"
				}
				fmt.Fprintln(stdout, line)
			}
		}
		return exitOK
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSEVERITY\tCATEGORY\tTITLE")
	for _, r := range reg.All() {
		m := r.Metadata()
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", m.ID, m.Severity, m.Category, m.Title)
	}
	tw.Flush()
	return exitOK
}

func cmdProfiles(stdout, stderr io.Writer) int {
	for _, name := range baselines.ProfileNames() {
		p, err := baselines.Profile(name)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitUsage
		}
		fmt.Fprintf(stdout, "%-11s %2d rules  %s\n", p.Name, len(p.Rules), p.Description)
	}
	return exitOK
}

func cmdDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text or json")
	failOn := fs.String("fail-on", "high", "exit 1 if a finding at or above this severity was introduced")
	reports, err := parseInterleaved(fs, args)
	if err != nil {
		return exitUsage
	}
	if len(reports) != 2 {
		fmt.Fprintln(stderr, "diff: want BEFORE.json AFTER.json")
		return exitUsage
	}
	threshold, err := finding.ParseSeverity(*failOn)
	if err != nil {
		fmt.Fprintln(stderr, "diff:", err)
		return exitUsage
	}
	before, err1 := readReport(reports[0])
	after, err2 := readReport(reports[1])
	if err := errors.Join(err1, err2); err != nil {
		fmt.Fprintln(stderr, "diff:", err)
		return exitUsage
	}
	c := verification.Compare(before, after)
	if *format == "json" {
		if err := reporting.JSONValue(stdout, c); err != nil {
			fmt.Fprintln(stderr, "diff:", err)
			return exitUsage
		}
	} else {
		section := func(title string, fs []finding.Finding) {
			fmt.Fprintf(stdout, "%s (%d)\n", title, len(fs))
			for _, f := range fs {
				fmt.Fprintf(stdout, "  [%s] %s %s\n", f.Severity, f.RuleID, reporting.Sanitize(f.Resource.String()))
			}
		}
		section("Resolved", c.Resolved)
		section("Introduced", c.Introduced)
		section("Persisting", c.Persisting)
		if len(c.Unverified) > 0 {
			section("Unverified (rule did not run after)", c.Unverified)
		}
		for _, cv := range c.Caveats {
			fmt.Fprintln(stdout, "caveat:", cv)
		}
	}
	if !after.Complete() {
		return exitIncomplete
	}
	if c.Regressed(threshold) {
		return exitFindings
	}
	return exitOK
}

func readReport(path string) (*finding.Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r, err := finding.ReadReport(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return r, nil
}

// printStats writes scan timings, slowest rules first, for performance
// reports (see .github/ISSUE_TEMPLATE/performance.yml).
func printStats(w io.Writer, st *hardex.Stats) {
	rules := append([]assessment.Timing(nil), st.Rules...)
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Duration > rules[j].Duration })
	fmt.Fprintf(w, "stats: %d objects, load %s, evaluate %s (%d rules)\n", st.Objects, st.Load.Round(time.Millisecond), st.Evaluate.Round(time.Millisecond), len(rules))
	for i, r := range rules {
		if i == 10 {
			break
		}
		fmt.Fprintf(w, "stats:   %-12s %10s  %d findings\n", r.RuleID, r.Duration.Round(time.Microsecond), r.Findings)
	}
}

// withoutFlag removes --name and --name=value (and "--name value") from args.
func withoutFlag(args []string, name string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-"+name || a == "--"+name:
			i++ // skip the value
		case strings.HasPrefix(a, "-"+name+"=") || strings.HasPrefix(a, "--"+name+"="):
		default:
			out = append(out, a)
		}
	}
	return out
}

// writeOutput renders to stdout, or, with a path, to that file: written
// completely or not at all, readable only by its owner (reports describe
// weaknesses), so an interrupted run or a full disk never leaves a
// truncated report where a baseline or diff input is expected.
func writeOutput(path string, stdout io.Writer, render func(io.Writer) error) error {
	if path == "" {
		return render(stdout)
	}
	return durable.WriteFile(path, 0o600, render)
}
