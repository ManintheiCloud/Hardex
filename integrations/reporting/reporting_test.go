package reporting

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
)

func sample() (*finding.Report, []assessment.Metadata) {
	f := finding.Finding{RuleID: "HX-WL-001", Title: "Privileged container", Severity: finding.Critical,
		Resource: finding.Resource{Kind: "Pod", Namespace: "x", Name: "evil\x1b[2Jname", Source: "a.yaml", Line: 3},
		Message:  "container \"c\" runs privileged", Remediation: "fix"}
	f.ComputeFingerprint()
	r := &finding.Report{Schema: finding.SchemaVersion, Tool: finding.Tool{Name: "hardex", Version: "test"},
		Findings: []finding.Finding{f}}
	r.Summarize()
	m := assessment.Metadata{ID: "HX-WL-001", Title: "Privileged container", Severity: finding.Critical,
		Category: "workloads", Description: "d", Rationale: "r", Remediation: "f"}
	return r, []assessment.Metadata{m}
}

func TestTextEscapesTerminalControlSequences(t *testing.T) {
	r, _ := sample()
	var buf bytes.Buffer
	if err := Text(&buf, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "\x1b") {
		t.Fatal("escape sequence from manifest reached text output")
	}
	if !strings.Contains(buf.String(), `evil\x1b[2Jname`) {
		t.Error("control character not shown in escaped form")
	}
}

func TestSARIFStructure(t *testing.T) {
	r, rules := sample()
	var buf bytes.Buffer
	if err := SARIF(&buf, r, rules); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []struct{ ID string } `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						Region struct{ StartLine int } `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 {
		t.Fatalf("unexpected SARIF shape: %s", buf.String())
	}
	res := doc.Runs[0].Results[0]
	if res.Level != "error" || res.Locations[0].PhysicalLocation.Region.StartLine != 3 {
		t.Errorf("result = %+v", res)
	}
}

func TestJSONRoundTrip(t *testing.T) {
	r, _ := sample()
	var buf bytes.Buffer
	if err := JSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	back, err := finding.ReadReport(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if back.Findings[0].Severity != finding.Critical || back.Findings[0].Fingerprint != r.Findings[0].Fingerprint {
		t.Error("report did not survive a JSON round trip")
	}
}
