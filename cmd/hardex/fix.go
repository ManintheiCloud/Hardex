package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/ManintheiCloud/Hardex"
	"github.com/ManintheiCloud/Hardex/core/cluster"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/policy"
	"github.com/ManintheiCloud/Hardex/core/remediation"
	"github.com/ManintheiCloud/Hardex/core/resource"
	"github.com/ManintheiCloud/Hardex/core/verification"
	"github.com/ManintheiCloud/Hardex/integrations/reporting"
	"github.com/ManintheiCloud/Hardex/kubernetes"
)

// Kinds whose pod template cannot be changed in place; fixing them in a
// cluster means recreating them, which Hardex will not do.
var immutableInCluster = map[string]string{
	"Pod": "pod specs are immutable; fix the controller or manifest that creates it",
	"Job": "job templates are immutable; fix the CronJob or manifest that creates it",
}

func cmdFix(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fix", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rulesFlag := fs.String("rules", "", "comma-separated rule IDs to remediate (default: all with an automatic fix; required with --apply)")
	maxRiskFlag := fs.String("max-risk", "medium", "highest change risk to include: low, medium or high")
	profile := fs.String("profile", "restricted", "profile used to find what to fix")
	configPath := fs.String("config", "", "policy configuration file (waived findings are not fixed)")
	format := fs.String("format", "text", "plan output: text or json")
	outDir := fs.String("out", "", "write patched manifests, new objects and plan.json to this directory (inputs are never modified)")
	kustomize := fs.Bool("kustomize", false, "with --out, write a Kustomize overlay (JSON 6902 patches + kustomization.yaml) instead of whole patched manifests")
	apply := fs.Bool("apply", false, "apply the plan to the live cluster (requires --cluster and --rules)")
	yes := fs.Bool("yes", false, "do not ask for confirmation before applying")
	backupDir := fs.String("backup-dir", "hardex-backups", "where to record backups before applying")
	failOn := fs.String("fail-on", "high", "after --apply, exit 1 if the verification scan finds an introduced finding at or above this severity")
	var cf clusterFlags
	cf.register(fs)
	paths, err := parseInterleaved(fs, args)
	if err != nil {
		return exitUsage
	}
	maxRisk, err := remediation.ParseRisk(*maxRiskFlag)
	if err != nil {
		fmt.Fprintln(stderr, "fix:", err)
		return exitUsage
	}
	threshold, err := finding.ParseSeverity(*failOn)
	if err != nil {
		fmt.Fprintln(stderr, "fix:", err)
		return exitUsage
	}
	selected := map[string]bool{}
	for _, id := range strings.Split(*rulesFlag, ",") {
		if id = strings.ToUpper(strings.TrimSpace(id)); id != "" {
			selected[id] = true
		}
	}
	fixers := kubernetes.Fixers()
	for id := range selected {
		if fixers[id] == nil {
			fmt.Fprintf(stderr, "fix: rule %s has no automatic fix\n", id)
			return exitUsage
		}
	}
	switch {
	case len(paths) == 0 && !cf.active():
		fmt.Fprintln(stderr, "fix: pass manifest paths, or --cluster")
		return exitUsage
	case len(paths) > 0 && cf.active():
		fmt.Fprintln(stderr, "fix: pass either paths or --cluster, not both")
		return exitUsage
	case *apply && !cf.active():
		fmt.Fprintln(stderr, "fix: --apply works on a live cluster; for manifests use --out and review the result")
		return exitUsage
	case *apply && len(selected) == 0:
		// ADR 0003: applying requires an explicit, per-run choice of what
		// to change. There is no "fix everything" switch.
		fmt.Fprintln(stderr, "fix: --apply requires --rules listing the rules to remediate")
		return exitUsage
	}

	cfg, err := loadConfig(*configPath, false)
	if err != nil {
		fmt.Fprintln(stderr, "fix:", err)
		return exitUsage
	}
	ctx := context.Background()

	// 1. Assess.
	var inv *resource.Inventory
	var client *cluster.Client
	var collErrs []string
	if cf.active() {
		if client, err = cf.connect(cluster.ReadOnly); err != nil {
			fmt.Fprintln(stderr, "fix:", err)
			return exitUsage
		}
		col, errs, _, err := cf.collect(ctx, client)
		if err != nil {
			fmt.Fprintln(stderr, "fix:", err)
			return exitUsage
		}
		inv, collErrs = col.Inventory, errs
	} else if inv, err = resource.Load(paths, stdin); err != nil {
		fmt.Fprintln(stderr, "fix:", err)
		return exitUsage
	}
	before, _, err := hardex.Scan(hardex.ScanOptions{Inventory: inv, Config: cfg, Profile: *profile, CollectionErrors: collErrs})
	if err != nil {
		fmt.Fprintln(stderr, "fix:", err)
		return exitUsage
	}
	if !before.Complete() {
		fmt.Fprintf(stderr, "fix: assessment incomplete, refusing to plan changes: %s\n", strings.Join(before.Errors, "; "))
		return exitIncomplete
	}

	// 2. Plan.
	plan, err := remediation.Build(inv, append(before.Findings, before.Waived...), fixers,
		remediation.Options{Rules: selected, MaxRisk: maxRisk, GuardResourceVersion: cf.active()})
	if err != nil {
		fmt.Fprintln(stderr, "fix:", err)
		return exitIncomplete
	}
	if cf.active() {
		var kept []remediation.ObjectPlan
		for _, o := range plan.Objects {
			if why, immutable := immutableInCluster[o.Target.Kind]; immutable {
				for _, f := range o.Fixes {
					plan.Skipped = append(plan.Skipped, remediation.Skip{RuleID: f.RuleID, Fingerprint: f.Fingerprint, Resource: o.Target.String(), Reason: why})
				}
				continue
			}
			kept = append(kept, o)
		}
		plan.Objects = kept
	}

	// 3. Predict the outcome by re-assessing the patched inventory.
	predicted, err := predict(inv, plan, cfg, *profile)
	if err != nil {
		fmt.Fprintln(stderr, "fix:", err)
		return exitIncomplete
	}
	cmp := verification.Compare(before, predicted)

	if *format == "json" {
		reporting.JSONValue(stdout, map[string]any{"plan": plan, "predicted": cmp})
	} else {
		printPlan(stdout, plan, cmp)
	}
	if *kustomize && *outDir == "" {
		fmt.Fprintln(stderr, "fix: --kustomize requires --out")
		return exitUsage
	}
	if *outDir != "" {
		write, what := writePlanDir, "patched object(s)"
		if *kustomize {
			write, what = writeKustomizeOverlay, "patch(es)"
		}
		if err := write(*outDir, plan); err != nil {
			fmt.Fprintln(stderr, "fix:", err)
			return exitUsage
		}
		fmt.Fprintf(stderr, "wrote %d %s, %d new object(s) and plan.json to %s\n", len(plan.Objects), what, len(plan.Creates), *outDir)
	}
	if !*apply {
		return exitOK
	}

	// 4. Apply (cluster only), with backup, automatic rollback on failure,
	// and verification by a fresh assessment.
	if len(plan.Objects) == 0 {
		fmt.Fprintln(stdout, "\nNothing to apply.")
		return exitOK
	}
	if len(plan.Creates) > 0 {
		fmt.Fprintf(stdout, "\nNote: %d new object(s) (e.g. NetworkPolicies) are never applied automatically; use --out and apply them after review.\n", len(plan.Creates))
	}
	if !*yes && !confirm(stdin, stdout, fmt.Sprintf("Apply %d patch(es) to context %q (%s)?", len(plan.Objects), client.Context(), client.Server())) {
		fmt.Fprintln(stdout, "Aborted; nothing was changed.")
		return exitOK
	}
	writer, err := cf.connect(cluster.ReadWrite)
	if err != nil {
		fmt.Fprintln(stderr, "fix:", err)
		return exitUsage
	}
	backup, err := remediation.NewBackup(*backupDir, writer.Context(), writer.Server(), plan.Objects, time.Now())
	if err != nil {
		fmt.Fprintln(stderr, "fix: cannot write backup, nothing was changed:", err)
		return exitUsage
	}
	fmt.Fprintf(stdout, "Backup: %s\n", backup.Path())
	res := remediation.ApplyAll(ctx, backup, clusterPatcher(writer))
	if res.Err != nil {
		fmt.Fprintf(stderr, "fix: apply failed: %v\n", res.Err)
		fmt.Fprintf(stderr, "fix: automatically rolled back %d object(s)\n", len(res.RolledBack))
		if res.RollbackErr != nil {
			fmt.Fprintf(stderr, "fix: ROLLBACK INCOMPLETE: %v\nfix: the backup %s records the remaining changes\n", res.RollbackErr, backup.Path())
		}
		return exitIncomplete
	}
	fmt.Fprintf(stdout, "Applied %d patch(es).\n", len(res.Applied))

	// Verification: success is defined by a fresh assessment, not by the
	// API accepting the patches (ADR 0003, constraint 3).
	col, errs, _, err := cf.collect(ctx, client)
	if err != nil {
		fmt.Fprintln(stderr, "fix: verification scan failed:", err)
		return exitIncomplete
	}
	after, _, err := hardex.Scan(hardex.ScanOptions{Inventory: col.Inventory, Config: cfg, Profile: *profile, CollectionErrors: errs})
	if err != nil {
		fmt.Fprintln(stderr, "fix: verification scan failed:", err)
		return exitIncomplete
	}
	actual := verification.Compare(before, after)
	targeted := map[string]bool{}
	for _, o := range plan.Objects {
		for _, f := range o.Fixes {
			targeted[f.Fingerprint] = true
		}
	}
	var unresolved []finding.Finding
	for _, f := range actual.Persisting {
		if targeted[f.Fingerprint] {
			unresolved = append(unresolved, f)
		}
	}
	fmt.Fprintf(stdout, "\nVerification: %d resolved, %d introduced, %d targeted finding(s) still present.\n", len(actual.Resolved), len(actual.Introduced), len(unresolved))
	for _, f := range actual.Introduced {
		fmt.Fprintf(stdout, "  introduced [%s] %s %s\n", f.Severity, f.RuleID, reporting.Sanitize(f.Resource.String()))
	}
	for _, f := range unresolved {
		fmt.Fprintf(stdout, "  unresolved [%s] %s %s\n", f.Severity, f.RuleID, reporting.Sanitize(f.Resource.String()))
	}
	if !after.Complete() {
		return exitIncomplete
	}
	if actual.Regressed(threshold) || len(unresolved) > 0 {
		fmt.Fprintf(stdout, "To undo: hardex rollback %s --cluster\n", backup.Path())
		return exitFindings
	}
	fmt.Fprintf(stdout, "Verified. To undo: hardex rollback %s --cluster\n", backup.Path())
	return exitOK
}

func cmdRollback(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	fs.SetOutput(stderr)
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	var cf clusterFlags
	cf.register(fs)
	files, err := parseInterleaved(fs, args)
	if err != nil {
		return exitUsage
	}
	if len(files) != 1 {
		fmt.Fprintln(stderr, "rollback: want exactly one backup file")
		return exitUsage
	}
	backup, err := remediation.LoadBackup(files[0])
	if err != nil {
		fmt.Fprintln(stderr, "rollback:", err)
		return exitUsage
	}
	cf.enabled = cf.enabled || !cf.inCluster
	writer, err := cf.connect(cluster.ReadWrite)
	if err != nil {
		fmt.Fprintln(stderr, "rollback:", err)
		return exitUsage
	}
	if writer.Server() != backup.Server {
		fmt.Fprintf(stderr, "rollback: backup was taken on %s but the current context points at %s; refusing\n", backup.Server, writer.Server())
		return exitUsage
	}
	pending := 0
	for _, o := range backup.Objects {
		if o.Applied && !o.RolledBack {
			pending++
			fmt.Fprintf(stdout, "  will restore %s\n", reporting.Sanitize(o.Target.String()))
		}
	}
	if pending == 0 {
		fmt.Fprintln(stdout, "Nothing to roll back.")
		return exitOK
	}
	if !*yes && !confirm(stdin, stdout, fmt.Sprintf("Restore %d object(s) on %s?", pending, writer.Server())) {
		fmt.Fprintln(stdout, "Aborted; nothing was changed.")
		return exitOK
	}
	res := remediation.Rollback(context.Background(), backup, clusterPatcher(writer))
	fmt.Fprintf(stdout, "Restored %d object(s).\n", len(res.RolledBack))
	if res.Err != nil {
		fmt.Fprintln(stderr, "rollback:", res.Err)
		return exitIncomplete
	}
	return exitOK
}

func clusterPatcher(c *cluster.Client) remediation.PatchFunc {
	return func(ctx context.Context, t remediation.Target, patch []remediation.Op) error {
		r, ok := cluster.ResourceForKind(t.Kind)
		if !ok {
			return fmt.Errorf("kind %s is not supported", t.Kind)
		}
		body, err := json.Marshal(patch)
		if err != nil {
			return err
		}
		ns := t.Namespace
		if resource.IsClusterScopedKind(t.Kind) {
			ns = ""
		}
		_, err = c.JSONPatch(ctx, r.ObjectPath(ns, t.Name), body)
		return err
	}
}

func predict(inv *resource.Inventory, plan *remediation.Plan, cfg *policy.Config, profile string) (*finding.Report, error) {
	patched := map[string]map[string]any{}
	for _, o := range plan.Objects {
		patched[o.Target.String()] = o.Patched
	}
	next := resource.NewInventory()
	next.Sources = inv.Sources
	for _, o := range inv.Objects {
		cp := *o
		if p, ok := patched[(remediation.Target{Kind: o.Kind, Namespace: o.EffectiveNamespace(), Name: o.Name}).String()]; ok {
			cp.Raw = p
		}
		next.Add(&cp)
	}
	for _, c := range plan.Creates {
		obj, err := resource.NewObject(c.Object, "<planned>", 0)
		if err != nil {
			return nil, err
		}
		next.Add(obj)
	}
	r, _, err := hardex.Scan(hardex.ScanOptions{Inventory: next, Config: cfg, Profile: profile})
	return r, err
}

func printPlan(w io.Writer, plan *remediation.Plan, cmp verification.Comparison) {
	fmt.Fprintf(w, "Remediation plan (dry run): %d object(s) to patch, %d new object(s), %d finding(s) skipped\n", len(plan.Objects), len(plan.Creates), len(plan.Skipped))
	for _, o := range plan.Objects {
		fmt.Fprintf(w, "\n%s  [risk: %s]\n", reporting.Sanitize(o.Target.String()), o.Risk)
		for _, f := range o.Fixes {
			where := ""
			if f.Container != "" {
				where = " [" + reporting.Sanitize(f.Container) + "]"
			}
			fmt.Fprintf(w, "  %s%s: %s (%s risk)\n", f.RuleID, where, f.Description, f.Risk)
		}
		for _, op := range o.Patch {
			if op.Op == "test" {
				continue
			}
			v, _ := json.Marshal(op.Value)
			if op.Op == "remove" {
				v = nil
			}
			fmt.Fprintf(w, "    %-7s %s %s\n", op.Op, reporting.Sanitize(op.Path), reporting.Sanitize(string(v)))
		}
	}
	for _, c := range plan.Creates {
		fmt.Fprintf(w, "\nNEW %s %s/%s  [risk: %s]\n  %s: %s\n", c.Object["kind"], resource.String(c.Object, "metadata", "namespace"),
			resource.String(c.Object, "metadata", "name"), c.Fix.Risk, c.Fix.RuleID, c.Fix.Description)
	}
	noFix := 0
	reasons := map[string]int{}
	for _, s := range plan.Skipped {
		if strings.HasPrefix(s.Reason, "no automatic fix") {
			noFix++
			continue
		}
		reasons[s.RuleID+": "+s.Reason]++
	}
	if len(reasons) > 0 {
		keys := make([]string, 0, len(reasons))
		for k := range reasons {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintln(w, "\nNot included:")
		for _, k := range keys {
			fmt.Fprintf(w, "  %dx %s\n", reasons[k], reporting.Sanitize(k))
		}
	}
	if noFix > 0 {
		fmt.Fprintf(w, "\n%d finding(s) need manual remediation (see `hardex rules <ID>`).\n", noFix)
	}
	fmt.Fprintf(w, "\nPredicted result: %d finding(s) resolved, %d introduced.\n", len(cmp.Resolved), len(cmp.Introduced))
}

func writePlanDir(dir string, plan *remediation.Plan) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	write := func(obj map[string]any) error {
		name := safeName(fmt.Sprint(obj["kind"], "-", resource.String(obj, "metadata", "namespace"), "-", resource.String(obj, "metadata", "name")))
		// Go through JSON so whole numbers render as integers (replicas: 1,
		// not 1.0), which the API server requires for integer fields.
		js, err := json.Marshal(obj)
		if err != nil {
			return err
		}
		data, err := yaml.JSONToYAML(js)
		if err != nil {
			return err
		}
		header := []byte("# Generated by hardex fix. Review before applying; comments and field order\n# from the original manifest are not preserved.\n")
		return os.WriteFile(filepath.Join(dir, name+".yaml"), append(header, data...), 0o644)
	}
	for _, o := range plan.Objects {
		if err := write(o.Patched); err != nil {
			return err
		}
	}
	for _, c := range plan.Creates {
		if err := write(c.Object); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "plan.json"), data, 0o644)
}

// safeName maps an object identity to a file name that cannot escape the
// output directory, whatever the (untrusted) object name contains.
func safeName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), ".")
	if out == "" {
		out = "object"
	}
	return out
}

func confirm(in io.Reader, out io.Writer, question string) bool {
	fmt.Fprintf(out, "%s Type 'yes' to continue: ", question)
	line, _ := bufio.NewReader(in).ReadString('\n')
	return strings.TrimSpace(line) == "yes"
}

// writeKustomizeOverlay writes the plan as a Kustomize overlay: one JSON 6902
// patch per object (including the guarding "test" operations, so the patch
// fails loudly if the base has changed), new objects as resources, and a
// kustomization.yaml tying them together. The user adds their base.
func writeKustomizeOverlay(dir string, plan *remediation.Plan) error {
	if err := os.MkdirAll(filepath.Join(dir, "patches"), 0o755); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# Generated by hardex fix. Uncomment and adjust the base below, then\n")
	b.WriteString("# review the result with: kubectl kustomize .\n")
	b.WriteString("apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n")
	b.WriteString("resources:\n  # - ../base\n")
	for _, c := range plan.Creates {
		name := safeName(fmt.Sprint(c.Object["kind"], "-", resource.String(c.Object, "metadata", "namespace"), "-", resource.String(c.Object, "metadata", "name"))) + ".yaml"
		js, err := json.Marshal(c.Object)
		if err != nil {
			return err
		}
		data, err := yaml.JSONToYAML(js)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(&b, "  - %s\n", name)
	}
	if len(plan.Objects) > 0 {
		b.WriteString("patches:\n")
	}
	for _, o := range plan.Objects {
		t := o.Target
		name := "patches/" + safeName(t.Kind+"-"+t.Namespace+"-"+t.Name) + ".json"
		data, err := json.MarshalIndent(o.Patch, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name), append(data, '\n'), 0o644); err != nil {
			return err
		}
		group, version := "", t.APIVersion
		if i := strings.Index(t.APIVersion, "/"); i >= 0 {
			group, version = t.APIVersion[:i], t.APIVersion[i+1:]
		}
		fmt.Fprintf(&b, "  - path: %s\n    target:\n", name)
		if group != "" {
			fmt.Fprintf(&b, "      group: %s\n", group)
		}
		fmt.Fprintf(&b, "      version: %s\n      kind: %s\n      name: %q\n", version, t.Kind, t.Name)
		if t.Namespace != "" {
			fmt.Fprintf(&b, "      namespace: %q\n", t.Namespace)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte(b.String()), 0o644); err != nil {
		return err
	}
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "plan.json"), data, 0o644)
}
