# RBAC defaults

`kubernetes/rbac/defaults.json` lists the RBAC objects that Kubernetes and kubeadm create by default. Hardex does not report them, but only if an object in the cluster grants no more than its default definition: names (`system:…`, `kubeadm:…`) and the `kubernetes.io/bootstrapping: rbac-defaults` label are not trusted on their own.

It also records what each aggregated default (`admin`, `edit`, `view`) grants once aggregated, its selectors, and the aggregation labels of the defaults (`view` is aggregated into `edit`, `edit` into `admin`). Hardex uses them for bindings to default roles that are not in the input, and to follow roles of the input that are labelled into a default.

Regenerate when a supported Kubernetes version is added or one is dropped (union over the supported versions):

```sh
for v in 1.34 1.35 1.36 1.37; do
  mkdir -p /tmp/rbac/$v
  for f in cluster-roles cluster-role-bindings controller-roles controller-role-bindings \
           namespace-roles namespace-role-bindings cluster-roles-featuregates; do
    curl -sfL -o /tmp/rbac/$v/$f.yaml \
      https://raw.githubusercontent.com/kubernetes/kubernetes/release-$v/plugin/pkg/auth/authorizer/rbac/bootstrappolicy/testdata/$f.yaml
  done
done
python3 tools/rbac-defaults/generate.py kubernetes/rbac/defaults.json tools/rbac-defaults/kubeadm.yaml /tmp/rbac/*
```

`kubeadm.yaml` is transcribed from kubeadm's source (files named at its top); check it against the new release. The kind end-to-end test fails if a stock kubeadm cluster has a default that is missing here.
