package registry

import "testing"

func TestParseRef(t *testing.T) {
	d := "sha256:" + "ab" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"
	cases := []struct{ in, reg, repo, tag, dig string }{
		{"nginx", dockerHub, "library/nginx", "latest", ""},
		{"nginx:1.27", dockerHub, "library/nginx", "1.27", ""},
		{"bitnami/redis:7", dockerHub, "bitnami/redis", "7", ""},
		{"ghcr.io/org/app:1.0@" + d, "ghcr.io", "org/app", "1.0", d},
		{"localhost:5000/app", "localhost:5000", "app", "latest", ""},
		{"registry.k8s.io/etcd:3.5.21-0", "registry.k8s.io", "etcd", "3.5.21-0", ""},
		{"r.example.com/a/b/c@" + d, "r.example.com", "a/b/c", "", d},
	}
	for _, c := range cases {
		r, err := ParseRef(c.in)
		if err != nil || r.Registry != c.reg || r.Repository != c.repo || r.Tag != c.tag || r.Digest != c.dig {
			t.Errorf("ParseRef(%q) = %+v, %v", c.in, r, err)
		}
	}
	for _, bad := range []string{"app@sha256:short", "@" + d} {
		if _, err := ParseRef(bad); err == nil {
			t.Errorf("ParseRef(%q) accepted", bad)
		}
	}
}

func TestParseChallenge(t *testing.T) {
	s, p := parseChallenge(`Bearer realm="https://auth.example.com/token",service="registry.example.com",scope="repository:a:pull"`)
	if s != "Bearer" || p["realm"] != "https://auth.example.com/token" || p["service"] != "registry.example.com" {
		t.Errorf("%s %v", s, p)
	}
}
