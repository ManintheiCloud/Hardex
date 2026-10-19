package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ManintheiCloud/Hardex"
	"github.com/ManintheiCloud/Hardex/core/cluster"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/history"
	"github.com/ManintheiCloud/Hardex/core/resource"
	"github.com/ManintheiCloud/Hardex/integrations/monitoring"
	"github.com/ManintheiCloud/Hardex/integrations/notify"
)

// webhookSecretEnv names the environment variable holding the webhook
// signing secret. Secrets are never accepted as flags, which would expose
// them in process listings and shell history.
const webhookSecretEnv = "HARDEX_WEBHOOK_SECRET"

func cmdMonitor(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("monitor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	interval := fs.Duration("interval", time.Hour, "time between assessments (minimum 1m)")
	once := fs.Bool("once", false, "run a single assessment and exit (for cron or CI)")
	historyDir := fs.String("history", "hardex-history", "directory recording every assessment")
	keep := fs.Int("keep", 500, "keep only the newest N assessments (0 = all)")
	baselinePath := fs.String("baseline", "", "approved JSON report; findings not in it are drift")
	eventsPath := fs.String("events", "-", "write events as JSON Lines to this file (- for stdout, empty to disable)")
	webhookURL := fs.String("webhook", "", "POST events to this https URL (signed with $"+webhookSecretEnv+" if set)")
	webhookFormat := fs.String("webhook-format", "generic", "webhook payload: generic or slack")
	notifyMin := fs.String("notify-min", "medium", "lowest severity that produces per-finding events")
	profile := fs.String("profile", "", "profile (default from config, else baseline)")
	configPath := fs.String("config", "", "policy configuration file")
	var mods multiFlag
	fs.Var(&mods, "module", "declarative rule module file (repeatable)")
	failOn := fs.String("fail-on", "high", "with --once, exit 1 on new findings (or baseline drift) at or above this severity")
	var cf clusterFlags
	cf.register(fs)
	paths, err := parseInterleaved(fs, args)
	if err != nil {
		return exitUsage
	}
	fail := func(err error) int { fmt.Fprintln(stderr, "monitor:", err); return exitUsage }
	switch {
	case len(paths) == 0 && !cf.active():
		return fail(fmt.Errorf("pass manifest paths or --cluster"))
	case len(paths) > 0 && cf.active():
		return fail(fmt.Errorf("pass either paths or --cluster, not both"))
	case !*once && *interval < time.Minute:
		return fail(fmt.Errorf("--interval must be at least 1m"))
	}
	for _, p := range paths {
		if p == "-" {
			return fail(fmt.Errorf("stdin cannot be assessed repeatedly; pass files or directories"))
		}
	}
	minSev, err := finding.ParseSeverity(*notifyMin)
	if err != nil {
		return fail(err)
	}
	threshold, err := finding.ParseSeverity(*failOn)
	if err != nil {
		return fail(err)
	}
	cfg, err := loadConfig(*configPath, false)
	if err != nil {
		return fail(err)
	}
	store, err := history.Open(*historyDir)
	if err != nil {
		return fail(err)
	}
	m := &monitoring.Monitor{Store: store, MinSeverity: minSev, Keep: *keep}
	if *baselinePath != "" {
		if m.Baseline, err = readReport(*baselinePath); err != nil {
			return fail(err)
		}
	}
	switch *eventsPath {
	case "":
	case "-":
		m.Sinks = append(m.Sinks, notify.JSONLines{W: stdout})
	default:
		f, err := os.OpenFile(*eventsPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return fail(err)
		}
		defer f.Close()
		m.Sinks = append(m.Sinks, notify.JSONLines{W: f})
	}
	if *webhookURL != "" {
		wh, err := notify.NewWebhook(*webhookURL, []byte(os.Getenv(webhookSecretEnv)), *webhookFormat)
		if err != nil {
			return fail(err)
		}
		if len(wh.Secret) == 0 && *webhookFormat == notify.FormatGeneric {
			fmt.Fprintf(stderr, "monitor: warning: $%s is not set; webhook requests will not be signed\n", webhookSecretEnv)
		}
		m.Sinks = append(m.Sinks, wh)
	}

	var client *cluster.Client
	if cf.active() {
		if client, err = cf.connect(cluster.ReadOnly); err != nil {
			return fail(err)
		}
	}

	// assess runs one assessment; it returns the exit status it implies.
	assess := func(ctx context.Context) int {
		opts := hardex.ScanOptions{Config: cfg, Profile: *profile, Modules: mods}
		if client != nil {
			col, errs, warns, err := cf.collect(ctx, client)
			if err != nil {
				fmt.Fprintln(stderr, "monitor: collection failed:", err)
				return exitIncomplete
			}
			opts.Inventory, opts.CollectionErrors, opts.CollectionWarnings = col.Inventory, errs, warns
		} else {
			inv, err := resource.Load(paths, stdin)
			if err != nil {
				fmt.Fprintln(stderr, "monitor:", err)
				return exitIncomplete
			}
			opts.Inventory = inv
		}
		report, _, err := hardex.Scan(opts)
		if err != nil {
			fmt.Fprintln(stderr, "monitor:", err)
			return exitIncomplete
		}
		res, err := m.Process(ctx, report)
		if err != nil {
			fmt.Fprintln(stderr, "monitor:", err)
			return exitIncomplete
		}
		for _, e := range res.Events {
			if e.Type == notify.AssessmentCompleted {
				fmt.Fprintf(stderr, "%s monitor: %s\n", time.Now().UTC().Format(time.RFC3339), e.Message)
			}
		}
		for _, e := range res.DeliveryErrors {
			fmt.Fprintln(stderr, "monitor: notification failed:", e)
		}
		switch {
		case !report.Complete() || len(res.DeliveryErrors) > 0:
			return exitIncomplete
		case res.Regressed(threshold):
			return exitFindings
		}
		return exitOK
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *once {
		return assess(ctx)
	}
	fmt.Fprintf(stderr, "monitor: assessing every %s; history in %s (Ctrl-C to stop)\n", *interval, store.Dir())
	monitoring.Every(ctx, *interval, func(ctx context.Context) { assess(ctx) })
	fmt.Fprintln(stderr, "monitor: stopped")
	return exitOK
}
