package reporting

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
)

// SARIF 2.1.0 output, suitable for GitHub code scanning and other platforms
// that ingest static-analysis results.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID                   string            `json:"id"`
	Name                 string            `json:"name"`
	ShortDescription     sarifText         `json:"shortDescription"`
	FullDescription      sarifText         `json:"fullDescription"`
	Help                 sarifText         `json:"help"`
	DefaultConfiguration map[string]string `json:"defaultConfiguration"`
	Properties           map[string]any    `json:"properties"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Suppressions        []sarifSuppress   `json:"suppressions,omitempty"`
	Properties          map[string]any    `json:"properties"`
}

type sarifSuppress struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string    `json:"level"`
	Message sarifText `json:"message"`
}

// SARIF writes the report as a SARIF 2.1.0 log.
func SARIF(w io.Writer, r *finding.Report, rules []assessment.Metadata) error {
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "hardex",
			Version:        r.Tool.Version,
			InformationURI: "https://github.com/ManintheiCloud/Hardex",
		}},
		Results: []sarifResult{},
	}
	for _, m := range rules {
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
			ID:                   m.ID,
			Name:                 ruleName(m.Title),
			ShortDescription:     sarifText{m.Title},
			FullDescription:      sarifText{m.Description},
			Help:                 sarifText{fmt.Sprintf("%s\n\nWhy: %s\n\nFix: %s", m.Description, m.Rationale, m.Remediation)},
			DefaultConfiguration: map[string]string{"level": level(m.Severity)},
			Properties: map[string]any{
				"security-severity": securitySeverity(m.Severity),
				"tags":              []string{"security", "kubernetes", m.Category},
			},
		})
	}
	add := func(f finding.Finding) {
		res := sarifResult{
			RuleID:              f.RuleID,
			Level:               level(f.Severity),
			Message:             sarifText{fmt.Sprintf("%s: %s", f.Resource, f.Message)},
			PartialFingerprints: map[string]string{"hardex/v1": f.Fingerprint},
			Properties: map[string]any{
				"severity": f.Severity.String(),
				"path":     f.Path,
			},
		}
		loc := sarifLocation{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: uri(f.Resource.Source)}}}
		if f.Resource.Line > 0 {
			loc.PhysicalLocation.Region = &sarifRegion{StartLine: f.Resource.Line}
		}
		res.Locations = []sarifLocation{loc}
		if f.Waiver != nil {
			res.Suppressions = []sarifSuppress{{Kind: "external", Justification: f.Waiver.Justification}}
		}
		run.Results = append(run.Results, res)
	}
	for _, f := range r.Findings {
		add(f)
	}
	for _, f := range r.Waived {
		add(f)
	}
	inv := sarifInvocation{ExecutionSuccessful: r.Complete()}
	for _, e := range r.Errors {
		inv.ToolExecutionNotifications = append(inv.ToolExecutionNotifications, sarifNotification{"error", sarifText{e}})
	}
	for _, wn := range r.Warnings {
		inv.ToolExecutionNotifications = append(inv.ToolExecutionNotifications, sarifNotification{"warning", sarifText{wn}})
	}
	run.Invocations = []sarifInvocation{inv}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	})
}

func level(s finding.Severity) string {
	switch {
	case s >= finding.High:
		return "error"
	case s == finding.Medium:
		return "warning"
	}
	return "note"
}

// securitySeverity maps to the CVSS-like 0-10 scale GitHub uses to bucket
// security alerts.
func securitySeverity(s finding.Severity) string {
	return [...]string{"1.0", "3.0", "5.5", "8.0", "9.5"}[s]
}

func ruleName(title string) string {
	var b strings.Builder
	up := true
	for _, r := range title {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			if up && r >= 'a' && r <= 'z' {
				r -= 'a' - 'A'
			}
			b.WriteRune(r)
			up = false
		} else {
			up = true
		}
	}
	return b.String()
}

func uri(source string) string {
	if source == "" || source == "<stdin>" {
		return "stdin"
	}
	return filepath.ToSlash(source)
}
