package main

import (
	"strings"

	"context"
	"flag"
	"fmt"
	"github.com/ManintheiCloud/Hardex/core/cluster"
	"github.com/ManintheiCloud/Hardex/core/resource"
	"github.com/ManintheiCloud/Hardex/integrations/reporting"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/ManintheiCloud/Hardex/baselines"
	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/modules"
	"github.com/ManintheiCloud/Hardex/core/policy"
	"github.com/ManintheiCloud/Hardex/integrations/admission"
	"github.com/ManintheiCloud/Hardex/kubernetes"
)

func cmdAdmission(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("admission", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", ":8443", "HTTPS listen address")
	certFile := fs.String("tls-cert", "/etc/hardex/tls/tls.crt", "TLS certificate (reloaded when it changes)")
	keyFile := fs.String("tls-key", "/etc/hardex/tls/tls.key", "TLS private key")
	modeFlag := fs.String("mode", "warn", "enforce (reject), warn (admit with warnings) or audit (log only)")
	denyAt := fs.String("deny-at", "high", "lowest severity that blocks in enforce mode (others become warnings)")
	profile := fs.String("profile", "baseline", "profile whose rules run at admission")
	configPath := fs.String("config", "", "policy configuration (waivers apply at admission)")
	var mods multiFlag
	fs.Var(&mods, "module", "declarative rule module file (repeatable)")
	preflight := fs.Bool("preflight", false, "do not serve: report which existing objects enforce mode would reject (from --cluster or manifest paths)")
	exclude := fs.String("exclude-namespaces", "kube-system,hardex,cert-manager", "with --preflight, namespaces the webhook excludes (its namespaceSelector)")
	format := fs.String("format", "text", "with --preflight: text or json")
	var cf clusterFlags
	cf.register(fs)
	paths, err := parseInterleaved(fs, args)
	if err != nil {
		return exitUsage
	}
	fail := func(err error) int { fmt.Fprintln(stderr, "admission:", err); return exitUsage }
	mode, err := admission.ParseMode(*modeFlag)
	if err != nil {
		return fail(err)
	}
	threshold, err := finding.ParseSeverity(*denyAt)
	if err != nil {
		return fail(err)
	}
	cfg, err := loadConfig(*configPath, false)
	if err != nil {
		return fail(err)
	}
	rules, err := admissionRules(*profile, mods, cfg)
	if err != nil {
		return fail(err)
	}
	if *preflight {
		return admissionPreflight(rules, cfg, threshold, *exclude, *format, paths, &cf, stdout, stderr)
	}
	if len(paths) > 0 || cf.active() {
		return fail(fmt.Errorf("paths and --cluster are only used with --preflight"))
	}
	h := &admission.Handler{Rules: rules, Config: cfg, Mode: mode, Threshold: threshold, Log: stdout}
	fmt.Fprintf(stderr, "admission: %s mode, %d rules, denying at %s and above; listening on %s\n", mode, len(rules), threshold, *listen)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := admission.Serve(ctx, *listen, *certFile, *keyFile, h); err != nil {
		return fail(err)
	}
	return exitOK
}

// admissionRules selects the profile's (and modules') rules that can run on
// a single object.
func admissionRules(profileName string, mods []string, cfg *policy.Config) ([]assessment.Rule, error) {
	var extra []assessment.Rule
	for _, m := range mods {
		rules, err := modules.Load(m)
		if err != nil {
			return nil, err
		}
		extra = append(extra, rules...)
	}
	reg, err := kubernetes.Registry(extra...)
	if err != nil {
		return nil, err
	}
	profile, err := baselines.Profile(profileName)
	if err != nil {
		return nil, err
	}
	for _, r := range extra {
		profile.Rules = append(profile.Rules, r.Metadata().ID)
	}
	rules, _, err := policy.SelectRules(reg, profile, cfg)
	if err != nil {
		return nil, err
	}
	return admission.AdmissionOnly(rules), nil
}

// admissionPreflight reports what enforce mode would reject among existing
// objects, so platform namespaces can be excluded (or findings waived)
// before enforcing. Pods that controllers create on demand (e.g. storage
// provisioner helpers) do not exist yet and are not seen: run warn mode and
// read the decision log for those.
func admissionPreflight(rules []assessment.Rule, cfg *policy.Config, threshold finding.Severity, exclude, format string,
	paths []string, cf *clusterFlags, stdout, stderr io.Writer) int {
	fail := func(err error) int { fmt.Fprintln(stderr, "admission:", err); return exitUsage }
	var inv *resource.Inventory
	switch {
	case cf.active() && len(paths) > 0:
		return fail(fmt.Errorf("pass either paths or --cluster, not both"))
	case cf.active():
		client, err := cf.connect(cluster.ReadOnly)
		if err != nil {
			return fail(err)
		}
		col, errs, _, err := cf.collect(context.Background(), client)
		if err != nil {
			return fail(err)
		}
		if len(errs) > 0 {
			return fail(fmt.Errorf("incomplete collection: %s", strings.Join(errs, "; ")))
		}
		inv = col.Inventory
	case len(paths) > 0:
		var err error
		if inv, err = resource.Load(paths, nil); err != nil {
			return fail(err)
		}
	default:
		return fail(fmt.Errorf("--preflight needs --cluster or manifest paths"))
	}
	excluded := map[string]bool{}
	for _, ns := range strings.Split(exclude, ",") {
		if ns = strings.TrimSpace(ns); ns != "" {
			excluded[ns] = true
		}
	}
	h := &admission.Handler{Rules: rules, Config: cfg, Mode: admission.Enforce, Threshold: threshold}
	denials := h.Preflight(inv, excluded)
	if format == "json" {
		reporting.JSONValue(stdout, denials)
	} else {
		printPreflight(stdout, denials, threshold, exclude)
	}
	if len(denials) > 0 {
		return exitFindings
	}
	return exitOK
}

func printPreflight(w io.Writer, denials []admission.Denial, threshold finding.Severity, exclude string) {
	if len(denials) == 0 {
		fmt.Fprintf(w, "Enforce mode (denying at %s) would reject none of the existing objects outside %s.\n", threshold, exclude)
		fmt.Fprintln(w, "Pods that controllers create on demand are not visible here: run warn mode and check the decision log before enforcing.")
		return
	}
	byNS := map[string][]admission.Denial{}
	var namespaces []string
	for _, d := range denials {
		ns := d.Namespace
		if ns == "" {
			ns = "(cluster-scoped)"
		}
		if byNS[ns] == nil {
			namespaces = append(namespaces, ns)
		}
		byNS[ns] = append(byNS[ns], d)
	}
	fmt.Fprintf(w, "Enforce mode (denying at %s) would reject %d existing objects in %d namespaces.\n", threshold, len(denials), len(namespaces))
	fmt.Fprintln(w, "A rejected controller cannot be updated, and the pods it creates are rejected: it stops scaling, rolling out and replacing failed pods.")
	for _, ns := range namespaces {
		fmt.Fprintf(w, "\n%s\n", reporting.Sanitize(ns))
		for _, d := range byNS[ns] {
			ids := map[string]bool{}
			var rules []string
			for _, f := range d.Findings {
				if !ids[f.RuleID] {
					ids[f.RuleID] = true
					rules = append(rules, f.RuleID)
				}
			}
			fmt.Fprintf(w, "  %s %s: %s\n", d.Kind, reporting.Sanitize(d.Name), strings.Join(rules, ", "))
		}
	}
	var nsOnly []string
	cluster := false
	for _, ns := range namespaces {
		if ns == "(cluster-scoped)" {
			cluster = true
		} else {
			nsOnly = append(nsOnly, ns)
		}
	}
	fmt.Fprintln(w, "\nFix what you own. For trusted platform components (storage, networking, monitoring agents),")
	fmt.Fprintln(w, "waive the specific findings in the policy configuration, or exclude the component's namespace")
	fmt.Fprintln(w, "in the webhook's namespaceSelector — only if everything in that namespace is trusted, since")
	fmt.Fprintln(w, "excluded namespaces are not checked at all. Namespaces above:")
	fmt.Fprintf(w, "  %s\n", strings.Join(nsOnly, ", "))
	if cluster {
		fmt.Fprintln(w, "Cluster-scoped objects (ClusterRoles, ClusterRoleBindings) cannot be excluded by namespace: fix or waive them.")
	}
	fmt.Fprintln(w, "Pods that controllers create on demand are not visible here: run warn mode and check the decision log too.")
}
