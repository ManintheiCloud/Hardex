# Contributing to Hardex

Thank you for helping make Kubernetes harder to compromise. Contributions of code, rules, fixtures, documentation, testing and security research are all welcome.

**Security vulnerabilities in Hardex must not be reported in public issues.** See [SECURITY.md](SECURITY.md).

## Ways to contribute

- **Report a false positive or false negative.** These are the most valuable bug reports a security tool can get. Use the issue template and include a minimal manifest.
- **Propose a rule.** Open a "Rule proposal" issue describing the weakness, the attacker benefit, how to detect it, and the remediation.
- **Improve mappings** to CIS, NSA/CISA or NIST, citing the exact version and control.
- **Add fixtures** — realistic insecure and hardened manifests strengthen every rule.
- **Documentation**, especially "Known limitations" for existing rules.

## Development

```sh
git clone https://github.com/ManintheiCloud/Hardex && cd hardex
make check            # gofmt, go vet, race-enabled tests, govulncheck
make build            # ./bin/hardex
go run ./tools/gendocs  # regenerate docs/rules.md after changing rule metadata
```

Go 1.24 or later is required to build; CI and releases use the latest stable Go.

## Pull request expectations

Every PR should:

1. Pass `make check`. CI runs the same.
2. Keep the hardened fixtures at zero findings and keep every rule's detection expectation passing.
3. Include tests: for a new rule, a detection expectation and at least one near-miss that must not fire.
4. Update `docs/rules.md` (generated) and any affected documentation.
5. Not add dependencies without justification in the PR description (see [ADR 0002](docs/adr/0002-go-with-minimal-dependencies.md)).
6. Keep findings free of secret values.

A step-by-step guide for new rules is in [docs/writing-rules.md](docs/writing-rules.md).

### Changes needing extra review

These require approval from two maintainers:

- Changing a rule's default severity, or moving a rule between profiles.
- Anything in `core/policy` (waivers, disabling, overrides) or `core/resource` (input handling).
- Anything that could make a previously reported weakness go unreported.

## Commit conventions

- Write commit messages in the imperative ("Add HX-NET-005 ...").
- Sign off your commits (`git commit -s`) to certify the [Developer Certificate of Origin](https://developercertificate.org/).
- Reference the issue a change addresses.

## Conduct

Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Releasing

Releases are cut by changing the `VERSION` file on `main` (together with the CHANGELOG entry). The release workflow then tests, builds, signs and publishes binaries and the container image, and creates the `v<VERSION>` tag and GitHub release. Pushing a `v*` tag by hand works too. See [docs/verifying-releases.md](docs/verifying-releases.md).
