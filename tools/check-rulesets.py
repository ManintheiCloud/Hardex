#!/usr/bin/env python3
"""Check that the repository's live rulesets match .github/rulesets/*.json,
and that the deployment environments in .github/rulesets/environments.json
are protected as described (a required reviewer, deployments only from the
listed branches and tags).

Release signatures name release.yml on refs/heads/main, so they are only as
trustworthy as main's protection (SECURITY.md, "Release integrity"). This
compares each committed ruleset with the live one of the same name and exits
non-zero on any difference: a missing or disabled ruleset, a changed target,
a removed rule or status check, an added exclusion. A live setting that the
committed file does not mention (a field GitHub added later) is ignored;
everything the file says must hold exactly.

Usage: check-rulesets.py OWNER/REPO [DIR]. Needs `gh` with read access.
Bypass actors are visible only to repository admins; when the API does not
return them, that one comparison is reported as unverified, not failed.
"""
import json
import pathlib
import subprocess
import sys


def gh(path):
    r = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"cannot read {path}: {(r.stderr or r.stdout).strip()}")
    return json.loads(r.stdout)


def canon(v):
    if isinstance(v, dict):
        return {k: canon(x) for k, x in sorted(v.items())}
    if isinstance(v, list):
        return sorted((canon(x) for x in v), key=lambda x: json.dumps(x, sort_keys=True))
    return v


def typed(v):
    return isinstance(v, list) and v and all(isinstance(x, dict) and "type" in x for x in v)


def diff(path, live, want, out):
    """Record every way live differs from want; keys want does not mention
    are ignored, rules are matched by type and status checks by name."""
    if isinstance(want, dict):
        if not isinstance(live, dict):
            out.append(f"{path}: expected {json.dumps(want)}, live {json.dumps(live)}")
            return
        for k in want:
            diff(f"{path}.{k}" if path else k, live.get(k), want[k], out)
        return
    if typed(want):
        live = live if isinstance(live, list) else []
        by_type = {x.get("type"): x for x in live if isinstance(x, dict)}
        for w in want:
            if w["type"] not in by_type:
                out.append(f"{path}: rule {w['type']} is missing")
            else:
                diff(f"{path}[{w['type']}]", by_type[w["type"]], w, out)
        for t in sorted(set(by_type) - {w["type"] for w in want}):
            out.append(f"{path}: live has rule {t}, not in the committed file")
        return
    if path.endswith("required_status_checks") and isinstance(want, list):
        names = lambda xs: {f"{x.get('context')} (app {x.get('integration_id')})" for x in xs or [] if isinstance(x, dict)}
        for n in sorted(names(want) - names(live)):
            out.append(f"{path}: required check {n} is missing")
        for n in sorted(names(live) - names(want)):
            out.append(f"{path}: live also requires {n}, not in the committed file")
        return
    if canon(live) != canon(want):
        out.append(f"{path}: expected {json.dumps(canon(want))}, live {json.dumps(canon(live))}")


def check_environments(repo, path):
    """The release environment must require a reviewer and deploy only from
    the listed refs; otherwise approval can be skipped. Returns failure."""
    if not path.exists():
        return False
    failed = False
    for name, want in sorted(json.loads(path.read_text()).items()):
        r = subprocess.run(["gh", "api", f"repos/{repo}/environments/{name}"], capture_output=True, text=True)
        if r.returncode != 0:
            print(f"FAIL environment {name}: does not exist or cannot be read")
            failed = True
            continue
        env = json.loads(r.stdout)
        problems = []
        rules = {x.get("type"): x for x in env.get("protection_rules") or []}
        if want.get("required_reviewers"):
            rev = rules.get("required_reviewers")
            if not rev or not rev.get("reviewers"):
                problems.append("no required reviewer")
        notes = []
        if "admins_can_bypass" in want:
            if "can_admins_bypass" not in env:
                notes.append("admin bypass not visible to this token (unverified)")
            elif env["can_admins_bypass"] != want["admins_can_bypass"]:
                problems.append(f"administrators can bypass: {env['can_admins_bypass']}, expected {want['admins_can_bypass']}")
        policy = env.get("deployment_branch_policy") or {}
        if "deployment_branch_policies" in want:
            if not policy.get("custom_branch_policies"):
                problems.append(f"deployments not limited to selected refs (policy: {json.dumps(policy)})")
            else:
                got = gh(f"repos/{repo}/environments/{name}/deployment-branch-policies?per_page=100")
                have = {(p["name"], p.get("type", "branch")) for p in got.get("branch_policies", [])}
                need = {(p["name"], p["type"]) for p in want["deployment_branch_policies"]}
                for n, t in sorted(need - have):
                    problems.append(f"{t} {n} is not allowed to deploy")
                for n, t in sorted(have - need):
                    problems.append(f"{t} {n} may also deploy, not in the committed file")
        if problems:
            failed = True
            print(f"FAIL environment {name}:")
            for p in problems:
                print(f"  {p}")
        else:
            print(f"ok   environment {name}" + ("; " + "; ".join(notes) if notes else ""))
    return failed


def main():
    repo = sys.argv[1]
    folder = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else ".github/rulesets")
    live = {r["name"]: r for r in gh(f"repos/{repo}/rulesets?per_page=100")}
    failed = check_environments(repo, folder / "environments.json")
    for f in sorted(folder.glob("*.json")):
        if f.name == "environments.json":
            continue
        want = json.loads(f.read_text())
        name = want["name"]
        if name not in live:
            print(f"FAIL {f.name}: no live ruleset named {name!r}")
            failed = True
            continue
        got = gh(f"repos/{repo}/rulesets/{live[name]['id']}")
        notes = []
        if "bypass_actors" in want and "bypass_actors" not in got:
            want = {k: v for k, v in want.items() if k != "bypass_actors"}
            notes.append("bypass actors not visible to this token (unverified)")
        problems = []
        diff("", got, want, problems)
        if problems:
            failed = True
            print(f"FAIL {f.name} ({name}):")
            for p in problems:
                print(f"  {p}")
        else:
            print(f"ok   {f.name} ({name})" + ("; " + "; ".join(notes) if notes else ""))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
