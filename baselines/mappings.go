package baselines

import (
	"sort"

	"github.com/ManintheiCloud/Hardex/core/finding"
)

// CISVersion names the CIS Kubernetes Benchmark version Hardex maps to
// item by item. It applies to Kubernetes 1.34 and 1.35; item numbering
// changes between benchmark versions, so mappings are reviewed whenever the
// version changes.
const CISVersion = "CIS Kubernetes Benchmark v2.0"

// NSAVersion names the NSA/CISA guidance Hardex maps to, by the exact
// section headings of its table of contents.
const NSAVersion = "NSA/CISA Kubernetes Hardening Guidance v1.2 (August 2022)"

// cisItems are the CIS v2.0 items Hardex maps to, with their titles. The
// list was taken from kube-bench's open-source (Apache-2.0) encoding of the
// benchmark (cfg/cis-2.0); a test checks every mapping refers to one of them.
var cisItems = map[string]string{
	"5.2.2":  "Minimize the admission of privileged containers",
	"5.2.3":  "Minimize the admission of containers wishing to share the host process ID namespace",
	"5.2.4":  "Minimize the admission of containers wishing to share the host IPC namespace",
	"5.2.5":  "Minimize the admission of containers wishing to share the host network namespace",
	"5.2.6":  "Minimize the admission of containers with allowPrivilegeEscalation",
	"5.2.7":  "Minimize the admission of root containers",
	"5.2.8":  "Minimize the admission of containers with the NET_RAW capability",
	"5.2.9":  "Minimize the admission of containers with capabilities assigned",
	"5.2.10": "Minimize the admission of Windows HostProcess containers",
	"5.2.11": "Minimize the admission of HostPath volumes",
	"5.2.12": "Minimize the admission of containers which use HostPorts",
	"5.6.2":  "Ensure that the seccomp profile is set to docker/default in your Pod definitions",
	"5.6.3":  "Apply SecurityContext to your Pods and Containers",
	"5.1.1":  "Ensure that the cluster-admin role is only used where required",
	"5.1.2":  "Minimize access to secrets",
	"5.1.3":  "Minimize wildcard use in Roles and ClusterRoles",
	"5.1.4":  "Minimize access to create pods",
	"5.1.6":  "Ensure that Service Account Tokens are only mounted where necessary",
	"5.1.8":  "Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster",
	"5.1.10": "Minimize access to the proxy sub-resource of nodes",
	"5.1.13": "Minimize access to the service account token creation",
	"5.3.2":  "Ensure that all Namespaces have NetworkPolicies defined",
	"5.4.1":  "Prefer using Secrets as files over Secrets as environment variables",
	"5.4.2":  "Consider external secret storage",
	"1.2.1":  "Ensure that the --anonymous-auth argument is set to false",
	"1.2.3":  "Ensure that the --DenyServiceExternalIPs is set",
	"1.2.5":  "Ensure that the --kubelet-certificate-authority argument is set as appropriate",
	"1.2.6":  "Ensure that the --authorization-mode argument is not set to AlwaysAllow",
	"1.2.8":  "Ensure that the --authorization-mode argument includes RBAC",
	"1.2.10": "Ensure that the admission control plugin AlwaysAdmit is not set",
	"1.2.14": "Ensure that the admission control plugin NodeRestriction is set",
	"1.2.15": "Ensure that the --profiling argument is set to false",
	"1.2.16": "Ensure that the --audit-log-path argument is set",
	"1.2.23": "Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate",
	"1.2.26": "Ensure that the --etcd-cafile argument is set as appropriate",
	"1.2.27": "Ensure that the --encryption-provider-config argument is set as appropriate",
	"1.3.2":  "Ensure that the --profiling argument is set to false",
	"1.4.1":  "Ensure that the --profiling argument is set to false",
	"2.1":    "Ensure that the --cert-file and --key-file arguments are set as appropriate",
	"2.2":    "Ensure that the --client-cert-auth argument is set to true",
	"2.3":    "Ensure that the --auto-tls argument is not set to true",
	"2.5":    "Ensure that the --peer-client-cert-auth argument is set to true",
	"2.6":    "Ensure that the --peer-auto-tls argument is not set to true",
	"3.2.1":  "Ensure that a minimal audit policy is created",
	"4.2.1":  "Ensure that the --anonymous-auth argument is set to false",
	"4.2.2":  "Ensure that the --authorization-mode argument is not set to AlwaysAllow",
	"4.2.4":  "Verify that if defined, the --read-only-port argument is set to 0",
}

// NSA/CISA v1.2 section headings (table of contents), as "Section › Subsection".
const (
	nsaPodEnforcement = "Kubernetes Pod security › Pod security enforcement"
	nsaNonRoot        = `Kubernetes Pod security › "Non-root" containers and "rootless" container engines`
	nsaImmutable      = "Kubernetes Pod security › Immutable container file systems"
	nsaImages         = "Kubernetes Pod security › Building secure container images"
	nsaTokens         = "Kubernetes Pod security › Protecting Pod service account tokens"
	nsaHardening      = "Kubernetes Pod security › Hardening container environments"
	nsaNetwork        = "Network separation and hardening"
	nsaNetPolicies    = "Network separation and hardening › Network policies"
	nsaResources      = "Network separation and hardening › Resource policies"
	nsaControlPlane   = "Network separation and hardening › Control plane hardening"
	nsaEtcd           = "Network separation and hardening › Control plane hardening › Etcd"
	nsaWorkers        = "Network separation and hardening › Worker node segmentation"
	nsaEncryption     = "Network separation and hardening › Encryption"
	nsaSecrets        = "Network separation and hardening › Secrets"
	nsaCloud          = "Network separation and hardening › Protecting sensitive cloud infrastructure"
	nsaAuthn          = "Authentication and authorization › Authentication"
	nsaRBAC           = "Authentication and authorization › Role-based access control"
	nsaAudit          = "Audit Logging and Threat Detection › Logging › Kubernetes native audit logging configuration"
	nsaThreatModel    = "Threat model"
	nsaUpgrading      = "Upgrading and application security practices"
)

// Mapping is the item-level guidance a built-in rule implements.
type Mapping struct {
	CIS []string
	NSA []string
}

// Mappings lists, per built-in rule, the CIS v2.0 items and NSA/CISA v1.2
// sections it implements. A rule's CIS list is empty when the benchmark has
// no corresponding item.
var Mappings = map[string]Mapping{
	"HX-WL-001":   {CIS: []string{"5.2.2"}, NSA: []string{nsaPodEnforcement}},
	"HX-WL-002":   {CIS: []string{"5.2.3", "5.2.4", "5.2.5"}, NSA: []string{nsaPodEnforcement}},
	"HX-WL-003":   {CIS: []string{"5.2.11"}, NSA: []string{nsaPodEnforcement}},
	"HX-WL-004":   {CIS: []string{"5.2.6"}, NSA: []string{nsaPodEnforcement}},
	"HX-WL-005":   {CIS: []string{"5.2.7"}, NSA: []string{nsaNonRoot}},
	"HX-WL-006":   {CIS: []string{"5.2.8", "5.2.9"}, NSA: []string{nsaPodEnforcement}},
	"HX-WL-007":   {CIS: []string{"5.2.9"}, NSA: []string{nsaPodEnforcement}},
	"HX-WL-008":   {CIS: []string{"5.6.2"}, NSA: []string{nsaHardening}},
	"HX-WL-009":   {CIS: []string{"5.6.3"}, NSA: []string{nsaImmutable}},
	"HX-WL-010":   {NSA: []string{nsaResources}},
	"HX-WL-011":   {NSA: []string{nsaImages}},
	"HX-WL-012":   {NSA: []string{nsaImages}},
	"HX-WL-013":   {CIS: []string{"5.1.6"}, NSA: []string{nsaTokens}},
	"HX-WL-014":   {CIS: []string{"5.2.12"}, NSA: []string{nsaPodEnforcement}},
	"HX-WL-015":   {CIS: []string{"5.6.3"}, NSA: []string{nsaHardening}},
	"HX-WL-016":   {CIS: []string{"5.6.3"}, NSA: []string{nsaHardening}},
	"HX-WL-017":   {CIS: []string{"5.6.3"}, NSA: []string{nsaPodEnforcement}},
	"HX-WL-018":   {CIS: []string{"5.6.3"}, NSA: []string{nsaPodEnforcement}},
	"HX-WL-019":   {NSA: []string{nsaPodEnforcement}},
	"HX-WL-020":   {CIS: []string{"5.2.10"}, NSA: []string{nsaPodEnforcement}},
	"HX-SEC-001":  {CIS: []string{"5.4.2"}, NSA: []string{nsaSecrets}},
	"HX-SEC-002":  {CIS: []string{"5.4.1"}, NSA: []string{nsaSecrets}},
	"HX-RBAC-001": {CIS: []string{"5.1.3"}, NSA: []string{nsaRBAC}},
	"HX-RBAC-002": {CIS: []string{"5.1.1"}, NSA: []string{nsaRBAC}},
	"HX-RBAC-003": {CIS: []string{"5.1.2"}, NSA: []string{nsaRBAC}},
	"HX-RBAC-004": {CIS: []string{"5.1.8"}, NSA: []string{nsaRBAC}},
	"HX-RBAC-005": {CIS: []string{"5.1.10", "5.1.13"}, NSA: []string{nsaRBAC}},
	"HX-RBAC-006": {CIS: []string{"5.1.4"}, NSA: []string{nsaRBAC}},
	"HX-RBAC-007": {NSA: []string{nsaAuthn, nsaRBAC}},
	"HX-RBAC-008": {CIS: []string{"5.1.6"}, NSA: []string{nsaRBAC, nsaTokens}},
	"HX-NET-001":  {CIS: []string{"5.3.2"}, NSA: []string{nsaNetPolicies}},
	"HX-NET-002":  {CIS: []string{"5.3.2"}, NSA: []string{nsaNetPolicies}},
	"HX-NET-003":  {NSA: []string{nsaNetwork}},
	"HX-NET-004":  {CIS: []string{"1.2.3"}, NSA: []string{nsaNetwork}},
	"HX-NET-005":  {NSA: []string{nsaNetwork}},
	"HX-NET-006":  {NSA: []string{nsaNetwork}},
	"HX-NET-007":  {NSA: []string{nsaUpgrading}},
	"HX-CP-001":   {CIS: []string{"1.2.1"}, NSA: []string{nsaAuthn}},
	"HX-CP-002":   {CIS: []string{"1.2.6", "1.2.8"}, NSA: []string{nsaRBAC}},
	"HX-CP-003":   {CIS: []string{"1.2.16", "3.2.1"}, NSA: []string{nsaAudit}},
	"HX-CP-004":   {CIS: []string{"1.2.15", "1.3.2", "1.4.1"}, NSA: []string{nsaControlPlane}},
	"HX-CP-005":   {CIS: []string{"1.2.10", "1.2.14"}, NSA: []string{nsaControlPlane}},
	"HX-CP-006":   {CIS: []string{"2.1", "2.2", "2.3", "2.5", "2.6", "1.2.23", "1.2.26"}, NSA: []string{nsaEtcd}},
	"HX-CP-007":   {CIS: []string{"1.2.27"}, NSA: []string{nsaEncryption}},
	"HX-CP-008":   {CIS: []string{"1.2.5"}, NSA: []string{nsaControlPlane}},
	"HX-CP-009":   {NSA: []string{nsaPodEnforcement, nsaControlPlane}},
	"HX-NODE-001": {CIS: []string{"4.2.1"}, NSA: []string{nsaWorkers}},
	"HX-NODE-002": {CIS: []string{"4.2.2"}, NSA: []string{nsaWorkers}},
	"HX-NODE-003": {CIS: []string{"4.2.4"}, NSA: []string{nsaWorkers}},
	"HX-NODE-004": {NSA: []string{nsaWorkers}},
	"HX-PATH-001": {NSA: []string{nsaThreatModel, nsaRBAC, nsaPodEnforcement}},
	"HX-PATH-002": {NSA: []string{nsaCloud, nsaTokens}},
}

// CISItem returns the title of a mapped CIS item.
func CISItem(id string) (string, bool) {
	t, ok := cisItems[id]
	return t, ok
}

// MappedReferences returns the item-level references for a rule: CIS items
// and NSA/CISA sections, followed by the rule's other references with the
// coarser CIS and NSA-CISA citations removed. Rules without a mapping keep
// their references unchanged.
func MappedReferences(ruleID string, existing []finding.Reference) []finding.Reference {
	m, ok := Mappings[ruleID]
	if !ok {
		return existing
	}
	var out []finding.Reference
	for _, id := range m.CIS {
		out = append(out, finding.Reference{Framework: "CIS", Control: CISVersion + " " + id + " " + cisItems[id], URL: cisURL})
	}
	for _, s := range m.NSA {
		out = append(out, finding.Reference{Framework: "NSA-CISA", Control: NSAVersion + " — " + s, URL: nsaURL})
	}
	for _, r := range existing {
		if r.Framework != "CIS" && r.Framework != "NSA-CISA" {
			out = append(out, r)
		}
	}
	return out
}

// MappedRuleIDs lists rules with an item-level mapping, for tests.
func MappedRuleIDs() []string {
	ids := make([]string, 0, len(Mappings))
	for id := range Mappings {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
