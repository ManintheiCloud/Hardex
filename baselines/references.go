// Package baselines holds Hardex's security profiles and the constructors
// rules use to cite external guidance.
//
// Mapping policy: Hardex cites guidance at the most precise level its
// maintainers have verified. Pod Security Standards controls are cited by
// name. NSA/CISA guidance is cited by section. CIS Kubernetes Benchmark items
// are cited at section level only until item-level mappings have been
// reviewed against a specific licensed benchmark version (see
// docs/baselines.md). An imprecise citation that is correct is preferred over
// a precise one that is wrong.
package baselines

import "github.com/ManintheiCloud/Hardex/core/finding"

const (
	pssURL  = "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
	cisURL  = "https://www.cisecurity.org/benchmark/kubernetes"
	nsaURL  = "https://media.defense.gov/2022/Aug/29/2003066362/1/1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF"
	nistURL = "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf"
)

// PSS cites a Pod Security Standards control, e.g. PSS("Baseline", "Privileged Containers").
func PSS(level, control string) finding.Reference {
	return finding.Reference{Framework: "PSS", Control: level + ": " + control, URL: pssURL}
}

// NSA cites a section of the NSA/CISA Kubernetes Hardening Guidance (v1.2).
func NSA(section string) finding.Reference {
	return finding.Reference{Framework: "NSA-CISA", Control: "Kubernetes Hardening Guidance v1.2 — " + section}
}

// CIS cites a section of the CIS Kubernetes Benchmark.
func CIS(section, title string) finding.Reference {
	return finding.Reference{Framework: "CIS", Control: "§" + section + " " + title, URL: cisURL}
}

// K8s cites upstream Kubernetes documentation.
func K8s(title, url string) finding.Reference {
	return finding.Reference{Framework: "Kubernetes", Control: title, URL: url}
}
