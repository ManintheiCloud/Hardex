package reporting

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	htmltemplate "html/template"
	"io"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/score"
)

// evidence is the data behind the HTML and Markdown evidence reports.
type evidence struct {
	Report *finding.Report
	Score  score.Result
	Digest string
	Rules  map[string]assessment.Metadata
	BySev  []sevGroup
}

type sevGroup struct {
	Severity string
	Findings []finding.Finding
}

// Digest returns the SHA-256 of the report's canonical JSON encoding, so
// an evidence document can be tied to the exact machine-readable report.
func Digest(r *finding.Report) string {
	b, _ := json.Marshal(r)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Evidence renders an evidence report ("html" or "markdown"). digest
// identifies the source report; when empty it is computed from r.
func Evidence(w io.Writer, format string, r *finding.Report, metas []assessment.Metadata, digest string) error {
	if digest == "" {
		digest = Digest(r)
	}
	ev := evidence{Report: r, Score: score.Compute(r, metas), Digest: digest, Rules: map[string]assessment.Metadata{}}
	for _, m := range metas {
		ev.Rules[m.ID] = m
	}
	for s := finding.Critical; s >= finding.Info; s-- {
		var fs []finding.Finding
		for _, f := range r.Findings {
			if f.Severity == s {
				fs = append(fs, f)
			}
		}
		if len(fs) > 0 {
			ev.BySev = append(ev.BySev, sevGroup{Severity: s.String(), Findings: fs})
		}
	}
	funcs := map[string]any{
		"time":  func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") },
		"upper": strings.ToUpper,
		"md":    mdEscape,
		"pct":   func(f float64) string { return fmt.Sprintf("%.1f", f) },
		"join":  strings.Join,
		"bar": func(f float64) string {
			n := int(f / 10)
			return strings.Repeat("█", n) + strings.Repeat("░", 10-n)
		},
	}
	switch format {
	case "html":
		t := htmltemplate.Must(htmltemplate.New("e").Funcs(funcs).Parse(htmlTemplate))
		return t.Execute(w, ev)
	case "markdown":
		t := texttemplate.Must(texttemplate.New("e").Funcs(funcs).Parse(markdownTemplate))
		return t.Execute(w, ev)
	}
	return fmt.Errorf("unknown evidence format %q", format)
}

// mdEscape keeps untrusted text from breaking Markdown tables or injecting
// HTML when the Markdown is rendered.
func mdEscape(s string) string {
	s = Sanitize(s)
	return strings.NewReplacer("|", `\|`, "<", "&lt;", ">", "&gt;", "`", "'", "\n", " ").Replace(s)
}

const markdownTemplate = `# Hardex security evidence report

| | |
|---|---|
| Generated | {{time .Report.GeneratedAt}} |
| Tool | {{.Report.Tool.Name}} {{md .Report.Tool.Version}} |
| Profile | {{md .Report.Profile}} |
| Inputs | {{range $i, $s := .Report.Inputs}}{{if $i}}, {{end}}{{md $s}}{{end}} |
| Objects assessed | {{.Report.ObjectsEvaluated}} |
| Rules evaluated | {{len .Report.RulesEvaluated}} |
| Report SHA-256 | ` + "`{{.Digest}}`" + ` |
{{if not .Score.Valid}}
> **Assessment incomplete.** {{range .Report.Errors}}{{md .}}; {{end}}The score below is not valid and results understate risk.
{{end}}
## Posture score

**{{pct .Score.Score}} / 100 — grade {{.Score.Grade}}**{{if .Score.GradeNote}} ({{.Score.GradeNote}}){{end}}

Weighted share of rules with no active findings (critical 10, high 5, medium 3, low 1, info 0.5). Active findings: {{.Report.Summary.Total}} (critical {{.Report.Summary.Critical}}, high {{.Report.Summary.High}}, medium {{.Report.Summary.Medium}}, low {{.Report.Summary.Low}}, info {{.Report.Summary.Info}}); accepted risks: {{.Report.Summary.Waived}}.

| Category | Score | Passing | Failing |
|---|---|---|---|
{{range .Score.Categories}}| {{md .Name}} | {{pct .Score}} | {{.Passed}} | {{.Failed}} |
{{end}}
## Framework evidence
{{range .Score.Frameworks}}
### {{md .Name}}

| Control | Status | Rules |
|---|---|---|
{{range .Controls}}| {{md .Name}} | {{if .Failed}}**FAIL** ({{.Failed}}/{{len .Rules}}){{else}}pass{{end}} | {{range $i, $r := .Rules}}{{if $i}}, {{end}}{{$r.ID}} ({{$r.Status}}){{end}} |
{{end}}{{end}}
## Findings
{{range .BySev}}
### {{upper .Severity}} ({{len .Findings}})

| Rule | Resource | Detail | Location |
|---|---|---|---|
{{range .Findings}}| {{.RuleID}} | {{md .Resource.String}} | {{md .Message}} | {{md .Resource.Source}}{{if .Resource.Line}}:{{.Resource.Line}}{{end}} |
{{end}}{{else}}
No active findings.
{{end}}{{if .Report.Waived}}
## Accepted risks

| Rule | Resource | Justification | Owner | Expires |
|---|---|---|---|---|
{{range .Report.Waived}}| {{.RuleID}} | {{md .Resource.String}} | {{md .Waiver.Justification}} | {{md .Waiver.Owner}} | {{.Waiver.Expires}} |
{{end}}{{end}}{{if .Report.Warnings}}
## Warnings
{{range .Report.Warnings}}
- {{md .}}{{end}}
{{end}}
---

*Compliance is not security. This report records which Hardex controls passed for the inputs listed above at the time shown; it does not certify that the environment is secure. Verify it against the JSON report with the SHA-256 above.*
`

const htmlTemplate = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hardex evidence report</title>
<style>
:root{--bg:#fff;--fg:#1b1d21;--muted:#5f6670;--line:#e3e6ea;--fail:#b42318;--pass:#1a7f37;--warn:#9a6700;--card:#f6f8fa}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--fg:#e6e8eb;--muted:#9aa3ad;--line:#2a2f37;--fail:#ff7b72;--pass:#56d364;--warn:#e3b341;--card:#161a20}}
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;margin:0;padding:24px 16px}
main{max-width:1000px;margin:0 auto}h1{font-size:1.6rem;margin:0 0 4px}h2{margin-top:2rem;border-bottom:1px solid var(--line);padding-bottom:4px}
table{border-collapse:collapse;width:100%;margin:8px 0;font-size:.9rem}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}.fail{color:var(--fail);font-weight:600}.pass{color:var(--pass)}.accepted{color:var(--warn)}
.score{display:flex;gap:24px;align-items:center;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px;margin:16px 0}
.big{font-size:2.6rem;font-weight:700}.muted{color:var(--muted)}code{font-size:.85em;word-break:break-all}
.banner{border:1px solid var(--fail);color:var(--fail);border-radius:8px;padding:12px;margin:12px 0}
.wrap{overflow-x:auto}
</style></head><body><main>
<h1>Hardex security evidence report</h1>
<div class="muted">{{time .Report.GeneratedAt}} · {{.Report.Tool.Name}} {{.Report.Tool.Version}} · profile {{.Report.Profile}}</div>
{{if not .Score.Valid}}<div class="banner"><strong>Assessment incomplete.</strong> {{range .Report.Errors}}{{.}}; {{end}}The score is not valid and results understate risk.</div>{{end}}
<div class="score"><div><div class="big">{{pct .Score.Score}}</div><div class="muted">of 100</div></div>
<div><div class="big">{{.Score.Grade}}</div><div class="muted">grade{{if .Score.GradeNote}} — {{.Score.GradeNote}}{{end}}</div></div>
<div class="muted">{{.Report.Summary.Total}} active findings (critical {{.Report.Summary.Critical}}, high {{.Report.Summary.High}}, medium {{.Report.Summary.Medium}}, low {{.Report.Summary.Low}}, info {{.Report.Summary.Info}}) · {{.Report.Summary.Waived}} accepted risks<br>
Score = weighted share of rules with no active findings (critical 10, high 5, medium 3, low 1, info 0.5).</div></div>
<table><tr><th>Inputs</th><td>{{join .Report.Inputs ", "}}</td></tr>
<tr><th>Objects assessed</th><td>{{.Report.ObjectsEvaluated}}</td></tr><tr><th>Rules evaluated</th><td>{{len .Report.RulesEvaluated}}</td></tr>
<tr><th>Report SHA-256</th><td><code>{{.Digest}}</code></td></tr></table>
<h2>Categories</h2><div class="wrap"><table><tr><th>Category</th><th>Score</th><th>Passing</th><th>Failing</th></tr>
{{range .Score.Categories}}<tr><td>{{.Name}}</td><td>{{pct .Score}}</td><td>{{.Passed}}</td><td{{if .Failed}} class="fail"{{end}}>{{.Failed}}</td></tr>{{end}}</table></div>
<h2>Framework evidence</h2>
{{range .Score.Frameworks}}<h3>{{.Name}}</h3><div class="wrap"><table><tr><th>Control</th><th>Status</th><th>Rules</th></tr>
{{range .Controls}}<tr><td>{{.Name}}</td><td>{{if .Failed}}<span class="fail">FAIL ({{.Failed}}/{{len .Rules}})</span>{{else}}<span class="pass">pass</span>{{end}}</td>
<td>{{range $i, $r := .Rules}}{{if $i}}, {{end}}<span class="{{$r.Status}}">{{$r.ID}}</span>{{end}}</td></tr>{{end}}</table></div>{{end}}
<h2>Findings</h2>
{{range .BySev}}<h3>{{upper .Severity}} ({{len .Findings}})</h3><div class="wrap"><table><tr><th>Rule</th><th>Resource</th><th>Detail</th><th>Fix</th></tr>
{{range .Findings}}<tr><td>{{.RuleID}}</td><td>{{.Resource.String}}<br><span class="muted">{{.Resource.Source}}{{if .Resource.Line}}:{{.Resource.Line}}{{end}}</span></td><td>{{.Message}}{{if .Path}}<br><code>{{.Path}}</code>{{end}}</td><td>{{.Remediation}}</td></tr>{{end}}
</table></div>{{else}}<p>No active findings.</p>{{end}}
{{if .Report.Waived}}<h2>Accepted risks</h2><div class="wrap"><table><tr><th>Rule</th><th>Resource</th><th>Justification</th><th>Owner</th><th>Expires</th></tr>
{{range .Report.Waived}}<tr><td>{{.RuleID}}</td><td>{{.Resource.String}}</td><td>{{.Waiver.Justification}}</td><td>{{.Waiver.Owner}}</td><td>{{.Waiver.Expires}}</td></tr>{{end}}</table></div>{{end}}
{{if .Report.Warnings}}<h2>Warnings</h2><ul>{{range .Report.Warnings}}<li>{{.}}</li>{{end}}</ul>{{end}}
<p class="muted"><em>Compliance is not security. This report records which Hardex controls passed for the inputs listed above at the time shown; it does not certify that the environment is secure. Verify it against the JSON report with the SHA-256 above.</em></p>
</main></body></html>
`
