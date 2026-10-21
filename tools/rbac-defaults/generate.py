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


def subject(s):
    ns = s.get("namespace", "")
    return f'{s["kind"]}/{ns}/{s["name"]}' if s["kind"] == "ServiceAccount" else f'{s["kind"]}/{s["name"]}'


def main():
    out, kubeadm, dirs = sys.argv[1], sys.argv[2], sys.argv[3:]
    roles, bindings, sources = {}, {}, {}
    files = [kubeadm]
    for d in dirs:
        import glob
        files += sorted(glob.glob(d + "/*.yaml"))
    for f in files:
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
    }
    with open(out, "w") as f:
        json.dump(data, f, indent=1, sort_keys=True)
        f.write("\n")
    print(f"{len(roles)} roles, {len(bindings)} bindings")


if __name__ == "__main__":
    main()
