package cloudiam

import (
	"os"
	"strings"
	"testing"

	"github.com/ManintheiCloud/Hardex/core/resource"
)

func privileges(t *testing.T, file string) map[string]*resource.Object {
	t.Helper()
	objs, err := Load([]string{"testdata/" + file})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*resource.Object{}
	for _, o := range objs {
		if o.Kind != Kind || o.APIVersion != APIVersion {
			t.Fatalf("unexpected object %s", o.Ref())
		}
		out[o.Name] = o
	}
	return out
}

func level(o *resource.Object) string { return resource.String(o.Raw, "spec", "privilege") }

func TestAWS(t *testing.T) {
	got := privileges(t, "aws.json")
	want := map[string]string{
		"arn:aws:iam::111122223333:role/s3-writer":   Limited,
		"arn:aws:iam::111122223333:role/ops":         Admin,      // AWS managed AdministratorAccess
		"arn:aws:iam::111122223333:role/deployer":    Escalation, // URL-encoded inline iam:PassRole on *
		"arn:aws:iam::111122223333:role/conditional": Admin,      // MFA-conditional * is ignored; default version of custom-admin is NotAction s3:* on *
	}
	for arn, w := range want {
		if o := got[arn]; o == nil || level(o) != w {
			t.Errorf("%s: got %v, want %s", arn, o, w)
		}
	}
	if r := resource.Strings(got["arn:aws:iam::111122223333:role/conditional"].Raw, "spec", "reasons"); len(r) != 1 || !strings.Contains(r[0], "custom-admin") {
		t.Errorf("reasons = %v", r)
	}
}

func TestGCP(t *testing.T) {
	got := privileges(t, "gcp.json")
	for email, w := range map[string]string{
		"ci@proj.iam.gserviceaccount.com":     Admin,
		"minter@proj.iam.gserviceaccount.com": Escalation,
		"reader@proj.iam.gserviceaccount.com": Limited, // the owner binding is conditional
	} {
		if o := got[email]; o == nil || level(o) != w {
			t.Errorf("%s: got %v, want %s", email, o, w)
		}
	}
	if _, ok := got["alice@example.com"]; ok {
		t.Error("users are not workload identities")
	}
}

func TestAzure(t *testing.T) {
	got := privileges(t, "azure.json")
	for id, w := range map[string]string{
		"aaaaaaaa-0000-0000-0000-000000000001": Admin,      // Contributor on the subscription
		"aaaaaaaa-0000-0000-0000-000000000002": Limited,    // Owner of one resource group
		"aaaaaaaa-0000-0000-0000-000000000003": Escalation, // User Access Administrator at the root management group
	} {
		if o := got[id]; o == nil || level(o) != w {
			t.Errorf("%s: got %v, want %s", id, o, w)
		}
	}
	if aliases := resource.Strings(got["aaaaaaaa-0000-0000-0000-000000000001"].Raw, "spec", "aliases"); len(aliases) != 1 || aliases[0] != "11111111-0000-0000-0000-000000000001" {
		t.Errorf("object ID alias = %v", aliases)
	}
	if len(got) != 3 {
		t.Errorf("users must be ignored: %d identities", len(got))
	}
}

func TestUnrecognised(t *testing.T) {
	f := t.TempDir() + "/x.json"
	os.WriteFile(f, []byte(`{"kind":"Something"}`), 0o600)
	if _, err := Load([]string{f}); err == nil || !strings.Contains(err.Error(), "not a recognised IAM export") {
		t.Errorf("err = %v", err)
	}
}

// IAM exports are operator-supplied but large and hand-editable: malformed
// input must be an error, never a panic.
func FuzzParse(f *testing.F) {
	for _, n := range []string{"aws.json", "gcp.json", "azure.json"} {
		b, _ := os.ReadFile("testdata/" + n)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) { Parse(b, "fuzz") })
}
