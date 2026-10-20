package secrets

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// The substring matchers replaced these regular expressions for speed; they
// must agree on every ASCII name.
var (
	credentialRE = regexp.MustCompile(`(?i)(passw(or)?d|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)`)
	benignRE     = regexp.MustCompile(`(?i)(_file|_path|_url|_uri|_endpoint|_host|_name|_user(name)?|_enabled|_ttl|_timeout|_header)$`)
)

func TestNameMatchersAgreeWithRegexps(t *testing.T) {
	parts := []string{"DB", "PASSWORD", "passwd", "Passwrd", "PASSWORD_FILE", "_", "-", "api", "key", "API_KEY", "api-key", "apikey",
		"access", "ACCESS_KEY", "private", "Private-Key", "secret", "SECRET_NAME", "token", "TOKEN_TTL", "credential", "_url",
		"_username", "_user", "_host", "x", "pass", "word", "_endpoint", "_header", "_timeout", "_enabled", "_path", "_uri"}
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		var b strings.Builder
		for j := 0; j < 1+r.Intn(4); j++ {
			b.WriteString(parts[r.Intn(len(parts))])
		}
		n := b.String()
		if credentialName(n) != credentialRE.MatchString(n) {
			t.Fatalf("credentialName(%q) = %v, regexp says %v", n, credentialName(n), credentialRE.MatchString(n))
		}
		if benignSuffix(n) != benignRE.MatchString(n) {
			t.Fatalf("benignSuffix(%q) = %v, regexp says %v", n, benignSuffix(n), benignRE.MatchString(n))
		}
	}
}
