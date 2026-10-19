package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/ManintheiCloud/Hardex"
	"github.com/ManintheiCloud/Hardex/core/cluster"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/fleet"
	"github.com/ManintheiCloud/Hardex/core/score"
	"github.com/ManintheiCloud/Hardex/integrations/reporting"
)

// cmdCompare compares saved reports from several clusters or environments.
func cmdCompare(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "text or json")
	var mods multiFlag
	fs.Var(&mods, "module", "rule module the reports were produced with (repeatable)")
	files, err := parseInterleaved(fs, args)
	if err != nil {
		return exitUsage
	}
	if len(files) < 2 {
		fmt.Fprintln(stderr, "compare: want two or more JSON reports")
		return exitUsage
	}
	var members []fleet.Member
	for _, f := range files {
		r, err := readReport(f)
		if err != nil {
			fmt.Fprintln(stderr, "compare:", err)
			return exitUsage
		}
		members = append(members, fleet.Member{Label: strings.TrimSuffix(filepath.Base(f), ".json"), Report: r})
	}
	return printFleet(members, mods, *format, stdout, stderr)
}

// cmdFleet scans several kubeconfig contexts and compares them.
func cmdFleet(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fleet", flag.ContinueOnError)
	fs.SetOutput(stderr)
	contexts := fs.String("contexts", "", "comma-separated kubeconfig contexts to assess (required)")
	kubeconfig := fs.String("kubeconfig", "", "kubeconfig file (default $KUBECONFIG or ~/.kube/config)")
	outDir := fs.String("out", "", "also save each cluster's JSON report in this directory")
	profile := fs.String("profile", "", "profile (default from config, else baseline)")
	configPath := fs.String("config", "", "policy configuration file")
	format := fs.String("format", "text", "text or json")
	failOn := fs.String("fail-on", "high", "exit 1 if any cluster has active findings at or above this severity")
	allowPartial := fs.Bool("allow-partial", false, "treat unreadable resources as warnings")
	var mods multiFlag
	fs.Var(&mods, "module", "declarative rule module file (repeatable)")
	if _, err := parseInterleaved(fs, args); err != nil {
		return exitUsage
	}
	fail := func(err error) int { fmt.Fprintln(stderr, "fleet:", err); return exitUsage }
	var names []string
	for _, c := range strings.Split(*contexts, ",") {
		if c = strings.TrimSpace(c); c != "" {
			names = append(names, c)
		}
	}
	if len(names) < 1 {
		return fail(fmt.Errorf("--contexts is required"))
	}
	threshold, err := finding.ParseSeverity(*failOn)
	if err != nil {
		return fail(err)
	}
	cfg, err := loadConfig(*configPath, false)
	if err != nil {
		return fail(err)
	}
	if *outDir != "" {
		if err := os.MkdirAll(*outDir, 0o700); err != nil {
			return fail(err)
		}
	}
	exit := exitOK
	var members []fleet.Member
	for _, name := range names {
		cf := clusterFlags{enabled: true, kubeconfig: *kubeconfig, context: name, allowPartial: *allowPartial}
		client, err := cf.connect(cluster.ReadOnly)
		if err != nil {
			fmt.Fprintf(stderr, "fleet: %s: %v\n", name, err)
			exit = exitIncomplete
			continue
		}
		col, errs, warns, err := cf.collect(context.Background(), client)
		if err != nil {
			fmt.Fprintf(stderr, "fleet: %s: %v\n", name, err)
			exit = exitIncomplete
			continue
		}
		r, _, err := hardex.Scan(hardex.ScanOptions{Inventory: col.Inventory, Config: cfg, Profile: *profile, Modules: mods,
			CollectionErrors: errs, CollectionWarnings: warns})
		if err != nil {
			return fail(err)
		}
		if *outDir != "" {
			f, err := os.OpenFile(filepath.Join(*outDir, safeName(name)+".json"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return fail(err)
			}
			reporting.JSON(f, r)
			f.Close()
		}
		if !r.Complete() {
			exit = exitIncomplete
		} else if r.HighestSeverity() >= threshold && exit == exitOK {
			exit = exitFindings
		}
		members = append(members, fleet.Member{Label: name, Report: r})
	}
	if len(members) == 0 {
		return exitIncomplete
	}
	if code := printFleet(members, mods, *format, stdout, stderr); code != exitOK {
		return code
	}
	return exit
}

func printFleet(members []fleet.Member, mods []string, format string, stdout, stderr io.Writer) int {
	metas, err := ruleMetadata(mods)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	c := fleet.Compare(members, metas)
	if format == "json" {
		reporting.JSONValue(stdout, c)
		return exitOK
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CLUSTER\tSCORE\tGRADE\tCRIT\tHIGH\tMED\tLOW\tPROFILE")
	for _, m := range c.Members {
		sc := fmt.Sprintf("%.1f", m.Score)
		if !m.Valid {
			sc = "n/a"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%s\n", reporting.Sanitize(m.Label), sc, m.Grade,
			m.Findings.Critical, m.Findings.High, m.Findings.Medium, m.Findings.Low, reporting.Sanitize(m.Profile))
	}
	tw.Flush()
	if len(c.Rows) == 0 {
		fmt.Fprintln(stdout, "\nNo failing controls in any cluster.")
	} else {
		fmt.Fprintln(stdout, "\nFailing controls (✗ fails, ✓ passes, · not evaluated); inconsistent controls first:")
		tw = tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		header := "RULE\tSEV"
		for _, m := range c.Members {
			header += "\t" + reporting.Sanitize(m.Label)
		}
		fmt.Fprintln(tw, header+"\tNOTE")
		for _, row := range c.Rows {
			line := row.RuleID + "\t" + row.Severity.String()
			for _, cell := range row.Cells {
				switch {
				case !cell.Evaluated:
					line += "\t·"
				case cell.Status == score.Fail:
					line += fmt.Sprintf("\t✗ %d", cell.Active)
				default:
					line += "\t✓"
				}
			}
			note := ""
			switch {
			case row.Inconsistent:
				note = "inconsistent across clusters"
			case row.FailingEverywhere:
				note = "fails everywhere"
			}
			fmt.Fprintln(tw, line+"\t"+note)
		}
		tw.Flush()
	}
	for _, cv := range c.Caveats {
		fmt.Fprintln(stdout, "caveat:", reporting.Sanitize(cv))
	}
	return exitOK
}
