package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/modules"
	"github.com/ManintheiCloud/Hardex/core/score"
	"github.com/ManintheiCloud/Hardex/integrations/reporting"
	"github.com/ManintheiCloud/Hardex/kubernetes"
)

// cmdReport renders an evidence report or score from a saved JSON report.
func cmdReport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "html", "html, markdown, or score (JSON score breakdown)")
	output := fs.String("o", "", "write to this file instead of stdout")
	var mods multiFlag
	fs.Var(&mods, "module", "rule module the report was produced with (repeatable)")
	files, err := parseInterleaved(fs, args)
	if err != nil {
		return exitUsage
	}
	fail := func(err error) int { fmt.Fprintln(stderr, "report:", err); return exitUsage }
	if len(files) != 1 {
		return fail(fmt.Errorf("want one JSON report (from scan --format json)"))
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		return fail(err)
	}
	r, err := finding.ReadReport(bytes.NewReader(data))
	if err != nil {
		return fail(err)
	}
	metas, err := ruleMetadata(mods)
	if err != nil {
		return fail(err)
	}
	// The digest is of the file as given, so `sha256sum report.json`
	// matches the value printed in the evidence report.
	sum := sha256.Sum256(data)
	var render func(io.Writer) error
	switch *format {
	case "score":
		render = func(w io.Writer) error { return reporting.JSONValue(w, score.Compute(r, metas)) }
	case "html", "markdown":
		render = func(w io.Writer) error {
			return reporting.Evidence(w, *format, r, metas, hex.EncodeToString(sum[:]))
		}
	default:
		return fail(fmt.Errorf("unknown format %q", *format))
	}
	if err := writeOutput(*output, stdout, render); err != nil {
		return fail(err)
	}
	return exitOK
}

func ruleMetadata(mods []string) ([]assessment.Metadata, error) {
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
	var metas []assessment.Metadata
	for _, r := range reg.All() {
		metas = append(metas, r.Metadata())
	}
	return metas, nil
}
