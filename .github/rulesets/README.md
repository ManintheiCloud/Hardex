# Repository rulesets

Releases are signed as "built by `.github/workflows/release.yml` on `refs/heads/main`", and that is the identity every verification step trusts (`docs/verifying-releases.md`). The signature therefore means something only if `main` and the release tags are protected. These rulesets are the protection; they are kept here so they are reviewable and can be re-applied.

| File | Protects |
|---|---|
| `main.json` | `main` changes only through pull requests whose required checks pass (unit tests, minimum Go, supply-chain, kind end-to-end, accuracy corpus, the Action on four runner types, CodeQL); no force-push or deletion. |
| `release-tags.json` | `v*` tags cannot be moved or deleted. |

Apply (repository admin), either:

```sh
gh api -X POST repos/ManintheiCloud/Hardex/rulesets --input .github/rulesets/main.json
gh api -X POST repos/ManintheiCloud/Hardex/rulesets --input .github/rulesets/release-tags.json
```

or in the web UI: **Settings → Rules → Rulesets → New ruleset → Import a ruleset**, once per file.

Check: `gh api repos/ManintheiCloud/Hardex/rulesets --jq '.[].name'`.
