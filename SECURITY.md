# Security policy

## Reporting a vulnerability

Please report vulnerabilities in Hardex **privately** using GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue, pull request or discussion.

Include, where possible:

- the affected version or commit;
- a description of the issue and its impact;
- a minimal reproduction (input files, command line);
- any suggested fix.

## What counts as a vulnerability in Hardex

Because Hardex is a security tool, failures that produce **false assurance** are treated as vulnerabilities, not ordinary bugs. In scope:

- Input that makes Hardex report fewer findings than it should without signalling an incomplete assessment (e.g. a crafted manifest that hides a privileged container from HX-WL-001, or causes a rule failure without exit code 3).
- Ways for scanned content to influence configuration, waivers or profiles.
- Resource exhaustion, crashes, or code execution from crafted input.
- Secret material leaking into reports, logs or SARIF.
- Terminal injection through report output.
- Supply-chain issues in Hardex's build or release process.

Out of scope: missing rules for weaknesses Hardex does not claim to detect (please open a rule proposal instead), and documented limitations.

## Our commitments

- Acknowledge your report within **3 business days**.
- Provide an initial assessment within **10 business days**.
- Work with you on a fix and coordinated disclosure, normally within **90 days** of the report; sooner for actively exploited issues.
- Credit you in the advisory, unless you prefer otherwise.

## Supported versions

Until 1.0, only the latest release receives security fixes.

| Version | Supported |
|---|---|
| latest 0.x | ✅ |
| older 0.x | ❌ |

## Release integrity

Releases are built and signed in GitHub Actions with no long-lived keys; verifiers trust the identity `https://github.com/ManintheiCloud/Hardex/.github/workflows/release.yml@refs/heads/main` (see `docs/verifying-releases.md`). That identity is only as trustworthy as the protection of `main`: anyone who can push to it can produce a validly signed release. `main` and the `v*` tags are protected by the rulesets in `.github/rulesets/` — changes only through pull requests with all required checks passing, no force-push, and immutable release tags. The release workflow checks the live rulesets against those files and refuses to publish when they differ. Report any release whose provenance does not point at a commit on `main` reached through a pull request.
