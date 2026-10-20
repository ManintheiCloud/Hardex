# Repository rulesets

Releases are signed as "built by `.github/workflows/release.yml` on `refs/heads/main`", and that is the identity every verification step trusts (`docs/verifying-releases.md`). The signature therefore means something only if `main` and the release tags are protected. These rulesets are the protection; they are kept here so they are reviewable and can be re-applied.

| File | Protects |
|---|---|
| `main.json` | `main` changes only through pull requests whose required checks pass (unit tests, minimum Go, supply-chain, kind end-to-end, accuracy corpus, the Action on four runner types, CodeQL); no force-push or deletion. |
| `release-tags.json` | `v*` tags cannot be moved or deleted. |
| `environments.json` | The `release` environment: a required reviewer, no administrator bypass, and deployments only from `main` and `v*` tags. `release.yml` publishes nothing until a reviewer approves the run. |

Apply (repository admin), either:

```sh
gh api -X POST repos/ManintheiCloud/Hardex/rulesets --input .github/rulesets/main.json
gh api -X POST repos/ManintheiCloud/Hardex/rulesets --input .github/rulesets/release-tags.json
```

or in the web UI: **Settings → Rules → Rulesets → New ruleset → Import a ruleset**, once per file.

The rulesets are applied (2026-10-20). The environment is configured in **Settings → Environments → release**: *Required reviewers* (at least one), *Allow administrators to bypass* off, *Deployment branches and tags: Selected* with branch `main` and tag `v*`.

`tools/check-rulesets.py ManintheiCloud/Hardex` compares the live rulesets and the release environment with these files and fails on any difference: a missing or disabled ruleset, a removed rule or required check, an added exclusion. It runs before every release (the release stops on a difference) and weekly in `trust-root.yml`. To change the protection, change the file here in a pull request and the live ruleset together; otherwise the next release refuses to run.
