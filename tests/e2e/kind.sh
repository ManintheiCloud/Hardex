#!/usr/bin/env bash
# End-to-end test against a real Kubernetes cluster (kind).
#
# Exercises what unit tests can only fake: the live API client under the
# least-privilege reader role, remediation apply and rollback, the node
# scanner DaemonSet reading a real kubelet's files, and the admission
# webhook behind the real API server.
#
# Needs: kind, kubectl, docker, jq, Go. Creates (and deletes) the cluster
# named by $CLUSTER (default hardex-e2e). Run with `make e2e`.
set -euo pipefail

CLUSTER="${CLUSTER:-hardex-e2e}"
IMAGE="ghcr.io/manintheicloud/hardex:e2e"
CERT_MANAGER="${CERT_MANAGER:-v1.21.2}"
WORK="$(mktemp -d)"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# On GitHub Actions, results are also annotations, readable without the log.
annotate() { [ -n "${GITHUB_ACTIONS:-}" ] && echo "::$1 title=e2e::$(echo "$2" | tr '\n' ' ' | cut -c1-900)" || true; }
pass() { echo "PASS: $*"; annotate notice "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; annotate error "FAIL: $*"; exit 1; }
CURRENT_STEP=""
step() { echo; echo "=== $*"; CURRENT_STEP="$*"; }
trap 'rc=$?; annotate error "command failed (exit $rc) in step \"$CURRENT_STEP\" at line $LINENO: $BASH_COMMAND"' ERR
cleanup() {
  if [ "${KEEP_CLUSTER:-}" != 1 ]; then kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

step "cluster"
kind create cluster --name "$CLUSTER" --wait 180s
kubectl cluster-info --context "kind-$CLUSTER"
export KUBECONFIG="$WORK/admin.kubeconfig"
kind get kubeconfig --name "$CLUSTER" > "$KUBECONFIG"
kubectl version

step "build"
make build
docker build -q -t "$IMAGE" --build-arg VERSION=e2e .
kind load docker-image --name "$CLUSTER" "$IMAGE"

step "workloads under assessment"
kubectl apply -f deploy/hardex-reader.yaml
for ns in shop ci; do kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f -; done
# The fixtures are deliberately insecure; only the objects are needed, not
# running containers, so controllers are scaled to zero.
kubectl apply -f tests/fixtures/insecure/rbac.yaml
# Objects the API server rejects on this platform (the Windows HostProcess
# pod) are expected to fail; the Deployment must be created.
kubectl apply -f tests/fixtures/insecure/workloads.yaml 2>&1 | tee "$WORK/apply.txt" || true
kubectl get deployment -n shop insecure-web >/dev/null || fail "fixture Deployment shop/insecure-web was not created: $(cat "$WORK/apply.txt")"
kubectl scale deployment -n shop insecure-web --replicas 0

step "live scan as the least-privilege reader"
server="$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.server}')"
ca="$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')"
token="$(kubectl -n hardex create token hardex --duration 1h)"
cat > "$WORK/reader.kubeconfig" <<EOF
apiVersion: v1
kind: Config
clusters: [{name: kind, cluster: {server: "$server", certificate-authority-data: "$ca"}}]
users: [{name: reader, user: {token: "$token"}}]
contexts: [{name: reader, context: {cluster: kind, user: reader}}]
current-context: reader
EOF
set +e
./bin/hardex scan --cluster --kubeconfig "$WORK/reader.kubeconfig" --profile restricted --format json --fail-on none --stats \
  -o "$WORK/live.json" 2> "$WORK/live.err"
code=$?
set -e
cat "$WORK/live.err"
[ "$code" = 0 ] || fail "live scan exited $code (3 means the reader role could not read something)"
jq -e '.objectsEvaluated > 20' "$WORK/live.json" >/dev/null || fail "too few objects collected"
jq -e '[.findings[] | select(.ruleId=="HX-WL-001" and .resource.kind=="Deployment" and .resource.name=="insecure-web")] | length == 1' "$WORK/live.json" >/dev/null \
  || fail "HX-WL-001 not found on shop/insecure-web"
jq -e '[.findings[] | select(.ruleId=="HX-RBAC-002")] | length >= 1' "$WORK/live.json" >/dev/null || fail "HX-RBAC-002 not found"
if jq -e '.warnings // [] | map(select(test("forbidden|cannot list"))) | length > 0' "$WORK/live.json" >/dev/null; then
  fail "reader role is missing permissions: $(jq -c '.warnings' "$WORK/live.json")"
fi
pass "live scan complete; $(jq '.objectsEvaluated' "$WORK/live.json") objects, $(jq '.summary.total' "$WORK/live.json") findings"

# The reader must not be able to read Secrets or exec.
for verb in "get secrets -A" "create pods/exec -n shop" "get nodes/proxy"; do
  if kubectl --kubeconfig "$WORK/reader.kubeconfig" auth can-i $verb >/dev/null 2>&1; then
    fail "reader can $verb"
  fi
done
pass "reader cannot read Secrets, exec, or use nodes/proxy"

step "remediation apply and rollback"
./bin/hardex fix --cluster --rules HX-WL-001 --max-risk high --apply --yes --backup-dir "$WORK/backups" --fail-on none | tee "$WORK/fix.txt"
priv="$(kubectl get deployment -n shop insecure-web -o jsonpath='{.spec.template.spec.containers[0].securityContext.privileged}')"
[ "$priv" != "true" ] || fail "fix did not remove privileged"
pass "fix applied (privileged=${priv:-unset})"
backup="$(ls "$WORK"/backups/*.json | head -1)"
./bin/hardex rollback "$backup" --cluster --yes
priv="$(kubectl get deployment -n shop insecure-web -o jsonpath='{.spec.template.spec.containers[0].securityContext.privileged}')"
[ "$priv" = "true" ] || fail "rollback did not restore the original value"
pass "rollback restored the original"

step "node scanner DaemonSet"
sed "s#image: ghcr.io/manintheicloud/hardex:[^ ]*#image: $IMAGE#" deploy/hardex-node.yaml | kubectl apply -f -
kubectl -n hardex-node rollout status daemonset/hardex-node --timeout 120s
sleep 5
node_logs="$(kubectl -n hardex-node logs daemonset/hardex-node --all-containers)"
echo "$node_logs" | grep '^node:' || true
report="$(echo "$node_logs" | awk '/^\{/{p=1} p{print} p&&/^\}/{exit}')"
echo "$node_logs" | grep -q 'kubelet configuration: /var/lib/kubelet/config.yaml' || fail "node scan did not read the kubelet configuration"
echo "$node_logs" | grep -q 'static pod manifests: /etc/kubernetes/manifests' || fail "node scan did not read static pod manifests"
echo "$report" | jq -e '.objectsEvaluated >= 2 and (.inputs | map(select(test("kube-apiserver"))) | length == 1)' >/dev/null \
  || fail "node scan report is missing the kubelet configuration or the API server manifest: $(echo "$report" | jq -c '{objectsEvaluated, inputs}')"
echo "$report" | jq -r '.findings[] | "  \(.ruleId) \(.resource.kind) \(.resource.name): \(.message)"' | head -20
pass "node scan read the real kubelet configuration and control-plane manifests"

step "admission webhook"
kubectl apply -f "https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER}/cert-manager.yaml"
kubectl -n cert-manager rollout status deployment/cert-manager-webhook --timeout 180s
sed "s#image: ghcr.io/manintheicloud/hardex:[^ ]*#image: $IMAGE#" deploy/hardex-admission.yaml > "$WORK/admission.yaml"
for i in 1 2 3 4 5 6; do kubectl apply -f "$WORK/admission.yaml" && break; sleep 10; done
kubectl -n hardex rollout status deployment/hardex-admission --timeout 180s
kubectl create namespace e2e-admission
cat > "$WORK/bad-pod.yaml" <<'EOF'
apiVersion: v1
kind: Pod
metadata: {name: bad, namespace: e2e-admission}
spec: {containers: [{name: c, image: busybox, securityContext: {privileged: true}}]}
EOF
for i in $(seq 1 12); do
  out="$(kubectl apply --dry-run=server -f "$WORK/bad-pod.yaml" 2>&1 || true)"
  echo "$out" | grep -q 'HX-WL-001' && break
  sleep 5
done
echo "$out"
echo "$out" | grep -qi 'warning.*HX-WL-001' || fail "admission webhook (warn mode) did not warn about a privileged pod"
pass "admission webhook warns through the real API server"

echo
echo "All end-to-end checks passed."
