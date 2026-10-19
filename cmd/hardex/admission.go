package main

import (
	"context"
	"flag"
	"fmt"
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
	if _, err := parseInterleaved(fs, args); err != nil {
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
