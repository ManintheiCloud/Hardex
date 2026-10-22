#!/usr/bin/env python3
"""Generate kubernetes/rbac/defaults.json: the RBAC objects Kubernetes and
kubeadm create by default, as sets of atomic permissions and subjects.

Hardex does not report these defaults (their broad grants are by design),
but only when an object in the cluster grants no more than its default
definition. The data is the union over the supported Kubernetes versions of
the API server's bootstrap policy, from kubernetes/kubernetes
plugin/pkg/auth/authorizer/rbac/bootstrappolicy/testdata/*.yaml (one
directory per release branch), plus kubeadm.yaml in this directory.

Usage: generate.py OUT.json KUBEADM.yaml VERSION_DIR...
"""
import json
import sys

import yaml


def docs(path):
    with open(path) as f:
        for d in yaml.safe_load_all(f):
            if not d:
                continue
            if d.get("kind") == "List":
                yield from d.get("items") or []
            else:
                yield d


def key(o):
    m = o.get("metadata") or {}
    if o["kind"] in ("Role", "RoleBinding"):
        return f'{o["kind"]}/{m.get("namespace", "")}/{m["name"]}'
    return f'{o["kind"]}/{m["name"]}'


def atoms(rules):
    out = set()
    for r in rules or []:
        verbs = r.get("verbs") or []
        for url in r.get("nonResourceURLs") or []:
            for v in verbs:
                out.add(f"url|{url}|{v}")
        for g in r.get("apiGroups") or []:
            for res in r.get("resources") or []:
                names = r.get("resourceNames") or ["*"]
                for n in names:
                    for v in verbs:
                        out.add(f"{g}|{res}|{n}|{v}")
    return out


def matches(selector, labels):
    """A Kubernetes label selector (matchLabels, matchExpressions)."""
    for k, v in (selector.get("matchLabels") or {}).items():
        if labels.get(k) != v:
            return False
    for e in selector.get("matchExpressions") or []:
        k, op, vals = e["key"], e["operator"], e.get("values") or []
        if op == "In" and labels.get(k) not in vals:
            return False
        if op == "NotIn" and k in labels and labels[k] in vals:
            return False
        if op == "Exists" and k not in labels:
            return False
        if op == "DoesNotExist" and k in labels:
            return False
    return True


def aggregate(objs):
    """The effective permissions of each aggregated ClusterRole among objs (one
    release's complete set): the union of the roles its selectors match,
    themselves resolved, as the API server's aggregation controller does."""
    crs = {o["metadata"]["name"]: o for o in objs if o.get("kind") == "ClusterRole"}
    memo = {}

    def resolve(name, stack=()):
        if name in memo:
            return memo[name]
        o = crs[name]
        out = set(atoms(o.get("rules")))
        agg = o.get("aggregationRule")
        if agg and name not in stack:
            for other, oo in crs.items():
                if other == name:
                    continue
                labels = (oo.get("metadata") or {}).get("labels") or {}
                if any(matches(sel, labels) for sel in agg.get("clusterRoleSelectors") or []):
                    out |= resolve(other, stack + (name,))
        memo[name] = out
        return out

    agg = {f"ClusterRole/{n}": (o["aggregationRule"].get("clusterRoleSelectors") or [], resolve(n))
           for n, o in crs.items() if o.get("aggregationRule")}
    # The aggregation labels of the defaults themselves (view carries
    # aggregate-to-edit, edit aggregate-to-admin): a role added to view
    # reaches edit and admin too.
    labels = {f"ClusterRole/{n}": {k: v for k, v in ((o.get("metadata") or {}).get("labels") or {}).items() if "aggregate-to-" in k}
              for n, o in crs.items()}
    return agg, {k: v for k, v in labels.items() if v}


def subject(s):
    ns = s.get("namespace", "")
    return f'{s["kind"]}/{ns}/{s["name"]}' if s["kind"] == "ServiceAccount" else f'{s["kind"]}/{s["name"]}'


def main():
    out, kubeadm, dirs = sys.argv[1], sys.argv[2], sys.argv[3:]
    roles, bindings, sources = {}, {}, {}
    aggregated, aggregation_labels = {}, {}
    files = [kubeadm]
    for d in dirs:
        import glob
        files += sorted(glob.glob(d + "/*.yaml"))
    for f in files:
        agg, labels = aggregate(list(docs(f)))
        for k, v in labels.items():
            aggregation_labels.setdefault(k, {}).update(v)
        for k, (selectors, perms) in agg.items():
            a = aggregated.setdefault(k, {"selectors": [], "permissions": set()})
            for sel in selectors:
                if sel not in a["selectors"]:
                    a["selectors"].append(sel)
            a["permissions"] |= perms
        for o in docs(f):
            if o.get("kind") in ("ClusterRole", "Role"):
                k = key(o)
                roles.setdefault(k, set()).update(atoms(o.get("rules")))
                if o.get("aggregationRule"):
                    roles[k].add("aggregated")
            elif o.get("kind") in ("ClusterRoleBinding", "RoleBinding"):
                k = key(o)
                rr = o["roleRef"]
                ref = f'{rr["kind"]}/{rr["name"]}'
                b = bindings.setdefault(k, {"roleRef": ref, "subjects": set()})
                if b["roleRef"] != ref:
                    sys.exit(f"{k}: roleRef differs between versions ({b['roleRef']} vs {ref})")
                b["subjects"].update(subject(s) for s in o.get("subjects") or [])
    data = {
        "source": "kubernetes bootstrappolicy testdata (" + ", ".join(d.rstrip("/").split("/")[-1] for d in dirs) + ") and kubeadm",
        "roles": {k: sorted(v) for k, v in sorted(roles.items())},
        "bindings": {k: {"roleRef": v["roleRef"], "subjects": sorted(v["subjects"])} for k, v in sorted(bindings.items())},
        # What each aggregated default ClusterRole grants once the API server
        # has aggregated it (admin, edit, view, ...), and the selectors it
        # aggregates by, so that roles in the input carrying those labels
        # are added to it.
        "aggregated": {k: {"selectors": v["selectors"], "permissions": sorted(v["permissions"])} for k, v in sorted(aggregated.items())},
        "aggregationLabels": dict(sorted(aggregation_labels.items())),
    }
    with open(out, "w") as f:
        json.dump(data, f, indent=1, sort_keys=True)
        f.write("\n")
    print(f"{len(roles)} roles, {len(bindings)} bindings, {len(aggregated)} aggregated")


if __name__ == "__main__":
    main()
