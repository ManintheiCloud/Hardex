package main

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/ManintheiCloud/Hardex/core/history"
	"github.com/ManintheiCloud/Hardex/integrations/reporting"
)

func cmdHistory(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text or json")
	last := fs.Int("last", 0, "show only the most recent N assessments")
	dirs, err := parseInterleaved(fs, args)
	if err != nil {
		return exitUsage
	}
	if len(dirs) != 1 {
		fmt.Fprintln(stderr, "history: want one history directory (as passed to scan --history)")
		return exitUsage
	}
	store, err := history.Open(dirs[0])
	if err != nil {
		fmt.Fprintln(stderr, "history:", err)
		return exitUsage
	}
	entries, warnings, err := store.List()
	if err != nil {
		fmt.Fprintln(stderr, "history:", err)
		return exitUsage
	}
	points := history.Trend(entries)
	if *last > 0 && len(points) > *last {
		points = points[len(points)-*last:]
	}
	if *format == "json" {
		reporting.JSONValue(stdout, map[string]any{"points": points, "warnings": warnings})
		return exitOK
	}
	if len(points) == 0 {
		fmt.Fprintln(stdout, "No assessments recorded yet. Record one with: hardex scan --history", dirs[0], "...")
		return exitOK
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME (UTC)\tPROFILE\tTOTAL\tCRIT\tHIGH\tMED\tLOW\tINFO\tNEW\tFIXED\tNOTE")
	for _, p := range points {
		var notes []string
		if !p.Complete {
			notes = append(notes, "INCOMPLETE")
		}
		if p.Unverified > 0 {
			notes = append(notes, fmt.Sprintf("%d unverified", p.Unverified))
		}
		notes = append(notes, p.Caveats...)
		s := p.Summary
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t+%d\t-%d\t%s\n", p.Time.UTC().Format("2006-01-02 15:04"), reporting.Sanitize(p.Profile),
			s.Total, s.Critical, s.High, s.Medium, s.Low, s.Info, p.Introduced, p.Resolved, reporting.Sanitize(strings.Join(notes, "; ")))
	}
	tw.Flush()
	if n := len(points); n >= 2 {
		first, latest := points[0].Summary, points[n-1].Summary
		fmt.Fprintf(stdout, "\nOver %d assessments: critical %d → %d, high %d → %d, total %d → %d.\n",
			n, first.Critical, latest.Critical, first.High, latest.High, first.Total, latest.Total)
	}
	for _, w := range warnings {
		fmt.Fprintln(stderr, "warning:", reporting.Sanitize(w))
	}
	return exitOK
}
