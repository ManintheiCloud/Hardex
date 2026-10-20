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
kubectl apply -f tests/fixtures/insecure/rbac.yaml
kubectl apply -f tests/e2e/insecure.yaml

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
code=0
./bin/hardex scan --cluster --kubeconfig "$WORK/reader.kubeconfig" --profile restricted --format json --fail-on none --stats \
  -o "$WORK/live.json" 2> "$WORK/live.err" || code=$?
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
# Findings on everything except the deliberately insecure fixtures, for
# false-positive review: stock components and Hardex's own deployments.
jq -r '.findings[] | select((.resource.namespace // "") as $n | $n != "shop" and $n != "ci")
  | "\(.ruleId) \(.severity) \(.resource.kind) \(.resource.namespace // "-")/\(.resource.name)\(if .resource.container then "["+.resource.container+"]" else "" end)"' \
  "$WORK/live.json" | sort | uniq > "$WORK/other.txt"
echo "Findings outside the fixtures ($(wc -l < "$WORK/other.txt")):"; cat "$WORK/other.txt"
if [ -n "${GITHUB_ACTIONS:-}" ]; then
  split -l 12 "$WORK/other.txt" "$WORK/other."
  for f in "$WORK"/other.??; do annotate notice "REVIEW: $(paste -sd ';' "$f")"; done
fi

# The reader must not be able to read Secrets or exec.
# (Subresources need --subresource: "nodes/proxy" alone means a node named proxy.)
for check in "get secrets -A" "create pods --subresource=exec -n shop" "get nodes --subresource=proxy" \
             "create serviceaccounts --subresource=token -A" "patch deployments -A"; do
  if kubectl --kubeconfig "$WORK/reader.kubeconfig" auth can-i $check >/dev/null 2>&1; then
    fail "reader can: $check"
  fi
done
# ...and the checks themselves must work: the admin can.
kubectl auth can-i get nodes --subresource=proxy >/dev/null || fail "can-i self-check failed"
pass "reader cannot read Secrets, exec, use nodes/proxy, mint tokens or write"

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

step "admission preflight against the live cluster"
# (`|| code=$?`: an expected non-zero exit must not trip the ERR trap.)
code=0
./bin/hardex admission --preflight --cluster --kubeconfig "$WORK/reader.kubeconfig" --format json > "$WORK/preflight.json" || code=$?
[ "$code" = 1 ] || fail "preflight should report denials (exit 1), got exit $code"
jq -e '[.[] | select(.namespace=="shop" and .name=="insecure-web")] | length == 1' "$WORK/preflight.json" >/dev/null \
  || fail "preflight did not predict that shop/insecure-web would be rejected"
jq -e '[.[] | select(.namespace=="hardex" or .namespace=="kube-system")] | length == 0' "$WORK/preflight.json" >/dev/null \
  || fail "preflight reported objects in excluded namespaces"
pass "preflight predicts enforce-mode rejections from the live cluster ($(jq length "$WORK/preflight.json") objects)"

step "admission webhook in enforce mode"
kubectl -n hardex patch deployment hardex-admission --type json \
  -p '[{"op":"replace","path":"/spec/template/spec/containers/0/args/1","value":"--mode=enforce"}]'
kubectl -n hardex rollout status deployment/hardex-admission --timeout 180s
for i in $(seq 1 12); do
  out="$(kubectl apply --dry-run=server -f "$WORK/bad-pod.yaml" 2>&1 || true)"
  echo "$out" | grep -qi 'denied' && break
  sleep 5
done
echo "$out"
echo "$out" | grep -qi 'denied' || fail "enforce mode did not reject a privileged pod"
echo "$out" | grep -q 'HX-WL-001' || fail "enforce mode rejection does not name the rule"
cat > "$WORK/good-pod.yaml" <<'POD'
apiVersion: v1
kind: Pod
metadata: {name: good, namespace: e2e-admission}
spec:
  automountServiceAccountToken: false
  securityContext: {runAsNonRoot: true, runAsUser: 65532, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: c
      image: registry.k8s.io/pause:3.10@sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a
      securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}
      resources: {requests: {cpu: 10m, memory: 16Mi}, limits: {cpu: 100m, memory: 32Mi}}
POD
kubectl apply --dry-run=server -f "$WORK/good-pod.yaml" || fail "enforce mode rejected a hardened pod"
pass "enforce mode rejects a privileged pod and admits a hardened one"

# Enforce mode also applies to platform components outside the excluded
# namespaces: kind's local-path provisioner runs root hostPath helper pods in
# local-path-storage, which enforce mode rejects (see docs/admission.md,
# "Before enforcing"). Prove the interaction, then return to warn mode.
cat > "$WORK/probe-pvc.yaml" <<'PVC'
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: probe, namespace: e2e-admission}
spec: {accessModes: [ReadWriteOnce], resources: {requests: {storage: 1Mi}}}
---
apiVersion: v1
kind: Pod
metadata: {name: probe, namespace: e2e-admission}
spec:
  automountServiceAccountToken: false
  securityContext: {runAsNonRoot: true, runAsUser: 65532, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: c
      image: registry.k8s.io/pause:3.10@sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a
      securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}
      resources: {requests: {cpu: 10m, memory: 16Mi}, limits: {cpu: 100m, memory: 32Mi}}
      volumeMounts: [{name: v, mountPath: /v}]
  volumes: [{name: v, persistentVolumeClaim: {claimName: probe}}]
PVC
kubectl apply -f "$WORK/probe-pvc.yaml"
for i in $(seq 1 24); do
  kubectl get events -n e2e-admission --field-selector reason=ProvisioningFailed -o jsonpath='{.items[*].message}' | grep -qi 'hardex\|denied' && break
  sleep 5
done
msg="$(kubectl get events -n e2e-admission --field-selector reason=ProvisioningFailed -o jsonpath='{.items[0].message}' 2>/dev/null)"
echo "provisioning under enforce: ${msg:-<no failure event>}"
echo "$msg" | grep -qi 'denied' || fail "expected enforce mode to block local-path helper pods (documented interaction), got: ${msg:-nothing}"
pass "documented interaction confirmed: enforce mode blocks the local-path provisioner's helper pods"
kubectl -n hardex patch deployment hardex-admission --type json \
  -p '[{"op":"replace","path":"/spec/template/spec/containers/0/args/1","value":"--mode=warn"}]'
kubectl -n hardex rollout status deployment/hardex-admission --timeout 180s
kubectl -n e2e-admission wait --for=jsonpath='{.status.phase}'=Bound pvc/probe --timeout 180s || fail "provisioning did not recover in warn mode"
pass "provisioning works again in warn mode"

step "scheduled scan and monitor CronJobs, run in the cluster"
sed "s#image: ghcr.io/manintheicloud/hardex:[^ ]*#image: $IMAGE#" deploy/hardex-cronjob.yaml | kubectl apply -f -
# No webhook receiver in the test cluster: events go to the job log only.
sed -e "s#image: ghcr.io/manintheicloud/hardex:[^ ]*#image: $IMAGE#" -e '/--webhook=/d' \
    -e '/^              env:$/,/key: signing-secret}$/d' deploy/hardex-monitor.yaml > "$WORK/monitor.yaml"
grep -q WEBHOOK "$WORK/monitor.yaml" && fail "could not strip the webhook from the monitor manifest"
kubectl apply -f "$WORK/monitor.yaml"
kubectl -n hardex create job scan-1 --from=cronjob/hardex-scan
kubectl -n hardex wait --for=condition=complete job/scan-1 --timeout 180s \
  || { kubectl -n hardex logs job/scan-1 | tail -20; fail "scan CronJob did not complete"; }
kubectl -n hardex logs job/scan-1 > "$WORK/scan-1.json"
jq -e '.objectsEvaluated > 20 and ((.errors // []) | length) == 0' "$WORK/scan-1.json" >/dev/null \
  || fail "in-cluster scan report is incomplete: $(jq -c '{objectsEvaluated, errors}' "$WORK/scan-1.json")"
for run in 1 2; do
  kubectl -n hardex create job "monitor-$run" --from=cronjob/hardex-monitor
  kubectl -n hardex wait --for=condition=complete "job/monitor-$run" --timeout 240s \
    || { kubectl -n hardex describe "job/monitor-$run" | tail -15; fail "monitor run $run did not complete: logs: $(kubectl -n hardex logs "job/monitor-$run" 2>&1 | tail -3 | tr '\n' ' ') pods: $(kubectl -n hardex get pods -l job-name=monitor-$run --no-headers 2>&1 | tr '\n' ' ') pvc: $(kubectl -n hardex get pvc --no-headers 2>&1 | tr '\n' ' ') events: $(kubectl -n hardex get events --sort-by=.lastTimestamp 2>&1 | grep -iv 'normal' | tail -6 | tr '\n' ' ')"; }
  kubectl -n hardex logs "job/monitor-$run" > "$WORK/monitor-$run.log" 2>&1
done
head -3 "$WORK/monitor-1.log"
grep '^{' "$WORK/monitor-1.log" | head -1 | jq -e . >/dev/null || fail "monitor emitted no JSON events"
grep -q 'since the previous assessment' "$WORK/monitor-2.log" || fail "second monitor run did not use the history volume: $(head -5 "$WORK/monitor-2.log")"
pass "scan and monitor CronJobs run in-cluster with the reader role; history persists between runs"

step "Hardex's own deployments, as deployed"
./bin/hardex scan --cluster --kubeconfig "$WORK/reader.kubeconfig" --profile restricted --format json --fail-on none -o "$WORK/final.json"
jq -r '.findings[] | select(.resource.namespace as $n | ["hardex","hardex-node","cert-manager"] | index($n))
  | "\(.ruleId) \(.severity) \(.resource.kind) \(.resource.namespace)/\(.resource.name)\(if .resource.container then "["+.resource.container+"]" else "" end)"' \
  "$WORK/final.json" | sort | uniq > "$WORK/own.txt"
echo "Findings on Hardex and cert-manager ($(wc -l < "$WORK/own.txt")):"; cat "$WORK/own.txt"
if [ -n "${GITHUB_ACTIONS:-}" ]; then
  split -l 12 "$WORK/own.txt" "$WORK/own."
  for f in "$WORK"/own.??; do [ -e "$f" ] && annotate notice "REVIEW-OWN: $(paste -sd ';' "$f")"; done
fi

crit="$(jq -r '[.findings[] | select((.resource.namespace=="hardex" or .resource.namespace=="hardex-node") and .severity=="critical") | "\(.ruleId) \(.resource.namespace)/\(.resource.name)"] | join(", ")' "$WORK/final.json")"
[ -z "$crit" ] || fail "Hardex's own deployments have critical findings: $crit"
pass "Hardex's own deployments have no critical findings"

echo
echo "All end-to-end checks passed."
