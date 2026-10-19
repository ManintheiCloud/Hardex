// Package cloudiam reads cloud IAM exports so that attack-path analysis can
// tell a harmless workload identity from one that controls the cloud
// account.
//
// Hardex never calls cloud APIs. The operator exports IAM data with the
// provider's own CLI and passes the files with --cloud-iam:
//
//	aws iam get-account-authorization-details --output json > aws-iam.json
//	gcloud projects get-iam-policy PROJECT --format json > gcp-iam.json
//	az role assignment list --all --output json > azure-roles.json
//
// Each file is recognised by its shape. The result is one CloudIdentity
// object per identity, added to the inventory, recording how privileged
// the identity is and why.
package cloudiam

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/ManintheiCloud/Hardex/core/resource"
)

// Kind is the inventory kind of the identities this package produces.
const (
	Kind       = "CloudIdentity"
	APIVersion = "hardex.dev/v1alpha1"
)

// Privilege levels, most powerful first.
const (
	Admin      = "admin"      // controls the account, project or subscription
	Escalation = "escalation" // can grant itself admin (IAM write, impersonation)
	Limited    = "limited"    // anything else that was found
)

// Provider names, matching what the attack-path analysis reads from
// ServiceAccount annotations.
const (
	AWS   = "aws"
	GCP   = "gcp"
	Azure = "azure"
)

// Identity is one cloud identity and its effective privilege.
type Identity struct {
	Provider  string
	ID        string   // role ARN, service account email, or principal (client) ID
	Aliases   []string // other identifiers (Azure principal name and object ID)
	Privilege string
	Reasons   []string
	Source    string
}

// Load reads IAM export files and returns their identities as inventory
// objects.
func Load(paths []string) ([]*resource.Object, error) {
	merged := map[string]*Identity{}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		ids, err := Parse(data, p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		for _, id := range ids {
			key := id.Provider + "/" + strings.ToLower(id.ID)
			if prev, ok := merged[key]; ok {
				prev.Reasons = append(prev.Reasons, id.Reasons...)
				prev.Aliases = append(prev.Aliases, id.Aliases...)
				if rank(id.Privilege) < rank(prev.Privilege) {
					prev.Privilege = id.Privilege
				}
				continue
			}
			merged[key] = id
		}
	}
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []*resource.Object
	for _, k := range keys {
		id := merged[k]
		reasons := uniq(id.Reasons)
		aliases := []any{}
		for _, a := range uniq(id.Aliases) {
			aliases = append(aliases, a)
		}
		rs := []any{}
		for _, r := range reasons {
			rs = append(rs, r)
		}
		raw := map[string]any{
			"apiVersion": APIVersion, "kind": Kind,
			"metadata": map[string]any{"name": id.ID},
			"spec": map[string]any{"provider": id.Provider, "id": id.ID, "aliases": aliases,
				"privilege": id.Privilege, "reasons": rs},
		}
		o, err := resource.NewObject(raw, id.Source, 0)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, nil
}

func rank(p string) int {
	switch p {
	case Admin:
		return 0
	case Escalation:
		return 1
	}
	return 2
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// Parse recognises an export by its shape.
func Parse(data []byte, source string) ([]*Identity, error) {
	trimmed := strings.TrimSpace(string(data))
	switch {
	case strings.HasPrefix(trimmed, "["):
		return parseAzure(data, source)
	case strings.Contains(trimmed, `"RoleDetailList"`):
		return parseAWS(data, source)
	case strings.Contains(trimmed, `"bindings"`):
		return parseGCP(data, source)
	}
	return nil, fmt.Errorf("not a recognised IAM export (aws iam get-account-authorization-details, gcloud projects get-iam-policy, az role assignment list)")
}

// ---- AWS ----

type awsPolicyDoc struct {
	Statement awsStatements `json:"Statement"`
}

type awsStatement struct {
	Effect      string    `json:"Effect"`
	Action      stringSet `json:"Action"`
	NotAction   stringSet `json:"NotAction"`
	Resource    stringSet `json:"Resource"`
	NotResource stringSet `json:"NotResource"`
	Condition   any       `json:"Condition"`
}

// Statement may be a single object or a list.
type awsStatements []awsStatement

func (s *awsStatements) UnmarshalJSON(b []byte) error {
	if strings.HasPrefix(strings.TrimSpace(string(b)), "{") {
		var one awsStatement
		if err := json.Unmarshal(b, &one); err != nil {
			return err
		}
		*s = awsStatements{one}
		return nil
	}
	var many []awsStatement
	err := json.Unmarshal(b, &many)
	*s = many
	return err
}

// stringSet is a JSON string or list of strings.
type stringSet []string

func (s *stringSet) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*s = stringSet{one}
		return nil
	}
	var many []string
	err := json.Unmarshal(b, &many)
	*s = many
	return err
}

// policyDocument decodes a policy document, which the AWS CLI returns
// either as JSON or as a URL-encoded JSON string.
func policyDocument(raw json.RawMessage) (*awsPolicyDoc, error) {
	var doc awsPolicyDoc
	if err := json.Unmarshal(raw, &doc); err == nil && doc.Statement != nil {
		return &doc, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	if dec, err := url.QueryUnescape(s); err == nil {
		s = dec
	}
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

// AWS managed policies known to grant admin or escalation, for exports
// that do not include managed policy documents.
var awsManaged = map[string]string{
	"arn:aws:iam::aws:policy/AdministratorAccess": Admin,
	"arn:aws:iam::aws:policy/IAMFullAccess":       Escalation,
	"arn:aws:iam::aws:policy/PowerUserAccess":     Limited, // excludes IAM
}

// Actions that let a principal grant itself more privilege.
var awsEscalation = []string{
	"iam:*", "iam:createpolicyversion", "iam:setdefaultpolicyversion", "iam:attachrolepolicy",
	"iam:attachuserpolicy", "iam:attachgrouppolicy", "iam:putrolepolicy", "iam:putuserpolicy",
	"iam:putgrouppolicy", "iam:updateassumerolepolicy", "iam:createaccesskey", "iam:createloginprofile",
	"iam:updateloginprofile", "iam:addusertogroup", "iam:passrole", "sts:assumerole", "sts:*",
}

func awsClassify(doc *awsPolicyDoc) (string, string) {
	best, why := Limited, ""
	for _, st := range doc.Statement {
		if !strings.EqualFold(st.Effect, "Allow") || st.Condition != nil {
			continue // conditional grants are not counted as unconditional power
		}
		allRes := len(st.NotResource) == 0 && contains(st.Resource, "*")
		if len(st.NotAction) > 0 && allRes {
			// "everything except X" over all resources is admin unless it
			// excludes IAM.
			if !matchesAny(st.NotAction, "iam:") {
				return Admin, "Allow NotAction " + strings.Join(st.NotAction, ",") + " on *"
			}
			continue
		}
		for _, a := range st.Action {
			la := strings.ToLower(a)
			if (la == "*" || la == "*:*") && allRes {
				return Admin, "Allow * on *"
			}
			for _, e := range awsEscalation {
				if la == e && allRes && rank(Escalation) < rank(best) {
					best, why = Escalation, "Allow "+a+" on *"
				}
			}
		}
	}
	return best, why
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func matchesAny(list []string, prefix string) bool {
	for _, x := range list {
		if strings.HasPrefix(strings.ToLower(x), prefix) || x == "*" {
			return true
		}
	}
	return false
}

func parseAWS(data []byte, source string) ([]*Identity, error) {
	var d struct {
		RoleDetailList []struct {
			Arn            string `json:"Arn"`
			RolePolicyList []struct {
				PolicyName     string          `json:"PolicyName"`
				PolicyDocument json.RawMessage `json:"PolicyDocument"`
			} `json:"RolePolicyList"`
			AttachedManagedPolicies []struct {
				PolicyName string `json:"PolicyName"`
				PolicyArn  string `json:"PolicyArn"`
			} `json:"AttachedManagedPolicies"`
		} `json:"RoleDetailList"`
		Policies []struct {
			Arn               string `json:"Arn"`
			PolicyVersionList []struct {
				Document         json.RawMessage `json:"Document"`
				IsDefaultVersion bool            `json:"IsDefaultVersion"`
			} `json:"PolicyVersionList"`
		} `json:"Policies"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	managed := map[string]*awsPolicyDoc{}
	for _, p := range d.Policies {
		for _, v := range p.PolicyVersionList {
			if v.IsDefaultVersion {
				if doc, err := policyDocument(v.Document); err == nil {
					managed[p.Arn] = doc
				}
			}
		}
	}
	var out []*Identity
	for _, r := range d.RoleDetailList {
		id := &Identity{Provider: AWS, ID: r.Arn, Privilege: Limited, Source: source}
		consider := func(level, why string) {
			if why == "" {
				return
			}
			if rank(level) < rank(id.Privilege) {
				id.Privilege = level
			}
			if level != Limited {
				id.Reasons = append(id.Reasons, why)
			}
		}
		for _, p := range r.RolePolicyList {
			doc, err := policyDocument(p.PolicyDocument)
			if err != nil {
				return nil, fmt.Errorf("role %s policy %s: %w", r.Arn, p.PolicyName, err)
			}
			level, why := awsClassify(doc)
			consider(level, "inline policy "+p.PolicyName+": "+why)
		}
		for _, m := range r.AttachedManagedPolicies {
			if doc, ok := managed[m.PolicyArn]; ok {
				level, why := awsClassify(doc)
				if why != "" {
					consider(level, "managed policy "+m.PolicyName+": "+why)
				}
			} else if level, ok := awsManaged[m.PolicyArn]; ok {
				consider(level, "managed policy "+m.PolicyName)
			}
		}
		out = append(out, id)
	}
	return out, nil
}

// ---- Google Cloud ----

var gcpAdminRoles = map[string]bool{"roles/owner": true, "roles/editor": true}

var gcpEscalationRoles = map[string]bool{
	"roles/iam.serviceAccountTokenCreator":    true,
	"roles/iam.serviceAccountUser":            true,
	"roles/iam.serviceAccountKeyAdmin":        true,
	"roles/iam.serviceAccountAdmin":           true,
	"roles/iam.workloadIdentityUser":          true,
	"roles/iam.roleAdmin":                     true,
	"roles/iam.securityAdmin":                 true,
	"roles/resourcemanager.projectIamAdmin":   true,
	"roles/resourcemanager.folderAdmin":       true,
	"roles/resourcemanager.organizationAdmin": true,
	"roles/container.admin":                   true,
	"roles/cloudfunctions.admin":              true,
	"roles/run.admin":                         true,
	"roles/compute.admin":                     true,
	"roles/deploymentmanager.editor":          true,
	"roles/cloudbuild.builds.editor":          true,
	"roles/composer.admin":                    true,
	"roles/dataproc.admin":                    true,
	"roles/iam.workloadIdentityPoolAdmin":     true,
	"roles/orgpolicy.policyAdmin":             true,
	"roles/secretmanager.admin":               true,
	"roles/iam.organizationRoleAdmin":         true,
}

func parseGCP(data []byte, source string) ([]*Identity, error) {
	var p struct {
		Bindings []struct {
			Role      string   `json:"role"`
			Members   []string `json:"members"`
			Condition any      `json:"condition"`
		} `json:"bindings"`
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	ids := map[string]*Identity{}
	for _, b := range p.Bindings {
		if b.Condition != nil {
			continue // conditional bindings are not counted as unconditional power
		}
		for _, m := range b.Members {
			email, ok := strings.CutPrefix(m, "serviceAccount:")
			if !ok {
				continue
			}
			id := ids[email]
			if id == nil {
				id = &Identity{Provider: GCP, ID: email, Privilege: Limited, Source: source}
				ids[email] = id
			}
			level := Limited
			switch {
			case gcpAdminRoles[b.Role]:
				level = Admin
			case gcpEscalationRoles[b.Role]:
				level = Escalation
			}
			if level != Limited {
				id.Reasons = append(id.Reasons, b.Role+" on the project")
			}
			if rank(level) < rank(id.Privilege) {
				id.Privilege = level
			}
		}
	}
	var out []*Identity
	for _, id := range ids {
		out = append(out, id)
	}
	return out, nil
}

// ---- Azure ----

var azureAdminRoles = map[string]bool{"Owner": true, "Contributor": true}
var azureEscalationRoles = map[string]bool{
	"User Access Administrator":               true,
	"Role Based Access Control Administrator": true,
	"Managed Identity Operator":               true,
}

func parseAzure(data []byte, source string) ([]*Identity, error) {
	var list []struct {
		PrincipalID        string `json:"principalId"`
		PrincipalName      string `json:"principalName"`
		PrincipalType      string `json:"principalType"`
		RoleDefinitionName string `json:"roleDefinitionName"`
		Scope              string `json:"scope"`
		Condition          any    `json:"condition"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	ids := map[string]*Identity{}
	for _, a := range list {
		if a.PrincipalType != "ServicePrincipal" || a.Condition != nil {
			continue
		}
		// Workload identity annotations carry the client (application) ID;
		// for service principals `az` reports it as principalName.
		key := a.PrincipalName
		if key == "" {
			key = a.PrincipalID
		}
		id := ids[key]
		if id == nil {
			id = &Identity{Provider: Azure, ID: key, Aliases: []string{a.PrincipalID}, Privilege: Limited, Source: source}
			ids[key] = id
		}
		level := Limited
		broad := isAzureBroadScope(a.Scope)
		switch {
		case azureAdminRoles[a.RoleDefinitionName] && broad:
			level = Admin
		case azureEscalationRoles[a.RoleDefinitionName] && broad:
			level = Escalation
		}
		if level != Limited || azureAdminRoles[a.RoleDefinitionName] || azureEscalationRoles[a.RoleDefinitionName] {
			id.Reasons = append(id.Reasons, a.RoleDefinitionName+" on "+a.Scope)
		}
		if rank(level) < rank(id.Privilege) {
			id.Privilege = level
		}
	}
	var out []*Identity
	for _, id := range ids {
		out = append(out, id)
	}
	return out, nil
}

// isAzureBroadScope reports whether a scope is a subscription, management
// group or the tenant root, rather than a resource group or resource.
func isAzureBroadScope(scope string) bool {
	s := strings.ToLower(strings.TrimSuffix(scope, "/"))
	if s == "" || s == "/" || strings.HasPrefix(s, "/providers/microsoft.management/managementgroups/") {
		return true
	}
	parts := strings.Split(strings.TrimPrefix(s, "/"), "/")
	return len(parts) == 2 && parts[0] == "subscriptions"
}
