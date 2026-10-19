package main

import (
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/ManintheiCloud/Hardex/core/imagesig"
	"github.com/ManintheiCloud/Hardex/core/sigstore"
	"github.com/ManintheiCloud/Hardex/integrations/reporting"
)

// sigstoreFlags select a keyless signer, with cosign's flag names.
type sigstoreFlags struct {
	identity, identityRegexp, issuer, issuerRegexp, trustedRoot string
}

func (s *sigstoreFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&s.identity, "certificate-identity", "", "keyless: required signer identity (certificate SAN, e.g. a workflow URL or email)")
	fs.StringVar(&s.identityRegexp, "certificate-identity-regexp", "", "keyless: required signer identity, as a regular expression (anchor it)")
	fs.StringVar(&s.issuer, "certificate-oidc-issuer", "", "keyless: required OIDC issuer, e.g. https://token.actions.githubusercontent.com")
	fs.StringVar(&s.issuerRegexp, "certificate-oidc-issuer-regexp", "", "keyless: required OIDC issuer, as a regular expression")
	fs.StringVar(&s.trustedRoot, "trusted-root", "", "keyless: Sigstore trusted_root.json (default: the embedded public-good root)")
}

func (s *sigstoreFlags) active() bool {
	return s.identity != "" || s.identityRegexp != "" || s.issuer != "" || s.issuerRegexp != ""
}

func (s *sigstoreFlags) policy() (sigstore.Policy, error) {
	p := sigstore.Policy{Identity: s.identity, Issuer: s.issuer}
	var err error
	if s.identityRegexp != "" {
		if p.IdentityRegexp, err = regexp.Compile(s.identityRegexp); err != nil {
			return p, fmt.Errorf("--certificate-identity-regexp: %w", err)
		}
	}
	if s.issuerRegexp != "" {
		if p.IssuerRegexp, err = regexp.Compile(s.issuerRegexp); err != nil {
			return p, fmt.Errorf("--certificate-oidc-issuer-regexp: %w", err)
		}
	}
	if (p.Identity == "") == (p.IdentityRegexp == nil) || (p.Issuer == "") == (p.IssuerRegexp == nil) {
		return p, errors.New("keyless verification needs one of --certificate-identity(-regexp) and one of --certificate-oidc-issuer(-regexp)")
	}
	return p, nil
}

func (s *sigstoreFlags) root() (*sigstore.TrustedRoot, error) {
	if s.trustedRoot != "" {
		return sigstore.LoadTrustedRoot(s.trustedRoot)
	}
	return sigstore.PublicGood(), nil
}

func (s *sigstoreFlags) keyless() (*imagesig.Keyless, error) {
	p, err := s.policy()
	if err != nil {
		return nil, err
	}
	r, err := s.root()
	if err != nil {
		return nil, err
	}
	return &imagesig.Keyless{Root: r, Policy: p}, nil
}

// cmdVerifyBlob verifies a file against a Sigstore bundle, offline — for
// example a Hardex release's SHA256SUMS, without installing cosign.
func cmdVerifyBlob(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify-blob", flag.ContinueOnError)
	fs.SetOutput(stderr)
	bundlePath := fs.String("bundle", "", "Sigstore bundle (.sigstore.json)")
	format := fs.String("format", "text", "text or json")
	var sf sigstoreFlags
	sf.register(fs)
	paths, err := parseInterleaved(fs, args)
	if err != nil {
		return exitUsage
	}
	fail := func(err error) int { fmt.Fprintln(stderr, "verify-blob:", err); return exitUsage }
	if len(paths) != 1 || *bundlePath == "" {
		return fail(errors.New("usage: hardex verify-blob --bundle FILE.sigstore.json --certificate-identity(-regexp) ... --certificate-oidc-issuer ... FILE"))
	}
	k, err := sf.keyless()
	if err != nil {
		return fail(err)
	}
	data, err := os.ReadFile(paths[0])
	if err != nil {
		return fail(err)
	}
	bundle, err := os.ReadFile(*bundlePath)
	if err != nil {
		return fail(err)
	}
	digest := sha256.Sum256(data)
	res, err := sigstore.Verify(bundle, sigstore.Options{Root: k.Root, Policy: k.Policy, Digest: digest[:]})
	if err != nil {
		fmt.Fprintln(stderr, "verify-blob: NOT VERIFIED:", err)
		return exitFindings
	}
	if *format == "json" {
		reporting.JSONValue(stdout, res)
		return exitOK
	}
	fmt.Fprintf(stdout, "Verified OK: %s\n  signer: %s\n  issuer: %s\n  signed: %s (%s)\n  log:    %s, index %d\n",
		paths[0], reporting.Sanitize(res.Identity), reporting.Sanitize(res.Issuer), res.SigningTime.Format("2006-01-02T15:04:05Z"),
		joinSources(res.TimeSources), res.LogURL, res.LogIndex)
	return exitOK
}

func joinSources(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += "; "
		}
		out += x
	}
	return out
}
