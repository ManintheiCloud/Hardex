# Posture score and evidence reports

## Evidence reports

```sh
hardex scan --cluster --format json -o report.json
hardex report report.json -o evidence.html               # self-contained HTML
hardex report report.json --format markdown -o evidence.md
hardex report report.json --format score                 # score breakdown as JSON
hardex scan ./k8s --format html -o evidence.html         # directly from a scan
```

An evidence report contains: the score and grade; per-category scores; **framework evidence** — for each framework Hardex cites (Pod Security Standards, NSA/CISA, CIS sections, upstream Kubernetes guidance), each control with the rules that implement it and whether they passed; all active findings with locations and fixes; accepted risks with justification, owner and expiry; and warnings.

It also records the **SHA-256 of the JSON report** it was generated from. With `hardex report`, that is the digest of the file as given, so `sha256sum report.json` reproduces it and ties the human-readable evidence to the machine-readable record.

All content from manifests is escaped (HTML-escaped by Go's `html/template`; Markdown table characters neutralised), so a hostile object name cannot inject markup into the report.

## How the score is computed

Every evaluated rule has a weight from its default severity:

| Severity | Weight |
|---|---|
| critical | 10 |
| high | 5 |
| medium | 3 |
| low | 1 |
| info | 0.5 |

**Score = 100 × (weight of rules with no active findings) ÷ (weight of all evaluated rules)**, rounded to one decimal.

- A rule fails if it has at least one active finding; the number of instances does not change the score (they are reported alongside it). Twenty privileged pods and one privileged pod are the same failed control.
- A rule whose only findings are waived counts as passing but is shown as **accepted**, not as passing.
- Grades: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F below. **Any active critical finding caps the grade at D.**
- An incomplete assessment (rule errors or unreadable cluster resources) has **no valid score**.

The formula is deliberately simple so anyone can recompute it. A score is evidence, not a verdict: compliance is not security, and a perfect score means only that the controls Hardex evaluates passed for the inputs it was given.

## Comparing clusters

```sh
hardex fleet --contexts prod-eu,prod-us,staging --out reports/
hardex compare reports/prod-eu.json reports/staging.json
```

`fleet` assesses each kubeconfig context and prints a matrix: score and grade per cluster, then every failing control with its status in each cluster. Controls that pass in some clusters and fail in others are listed first as **inconsistent across clusters** — usually the cheapest wins, because the fix already exists somewhere. Clusters assessed with different profiles, or incompletely, are flagged.
