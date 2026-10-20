package admission

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// largeDeployment is close to the biggest object the API server accepts
// (~1.5 MiB): 40 containers with 300 environment variables each.
func largeDeployment() string {
	var cs []string
	for c := 0; c < 40; c++ {
		var env []string
		for e := 0; e < 300; e++ {
			env = append(env, fmt.Sprintf(`{"name":"VAR_%d","value":"%s"}`, e, strings.Repeat("v", 80)))
		}
		cs = append(cs, fmt.Sprintf(`{"name":"c%d","image":"r.example.com/a:1","env":[%s],"securityContext":{"privileged":%v}}`, c, strings.Join(env, ","), c == 39))
	}
	return `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"big"},"spec":{"selector":{"matchLabels":{"a":"b"}},"template":{"metadata":{"labels":{"a":"b"}},"spec":{"containers":[` + strings.Join(cs, ",") + `]}}}}`
}

func largeClusterRole() string {
	var rules []string
	for i := 0; i < 2000; i++ {
		rules = append(rules, fmt.Sprintf(`{"apiGroups":["g%d.example.com"],"resources":["r%d"],"verbs":["get","list"]}`, i, i))
	}
	rules = append(rules, `{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}`)
	return `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"big"},"rules":[` + strings.Join(rules, ",") + `]}`
}

func reviewBody(kind, group, version, object string) string {
	return `{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"u","kind":{"group":"` + group + `","version":"` + version + `","kind":"` + kind + `"},"namespace":"shop","operation":"CREATE","object":` + object + `}}`
}

var loadCases = []struct {
	name, body string
	allowed    bool
}{
	{"compliant-pod", reviewBody("Pod", "", "v1", compliantPod), true},
	{"privileged-pod", reviewBody("Pod", "", "v1", privilegedPod), false},
	{"large-deployment", reviewBody("Deployment", "apps", "v1", largeDeployment()), false},
	{"large-clusterrole", reviewBody("ClusterRole", "rbac.authorization.k8s.io", "v1", largeClusterRole()), false},
}

func serve(h http.Handler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// BenchmarkDecide measures a full request: decode, evaluate, encode.
func BenchmarkDecide(b *testing.B) {
	h := handler(&testing.T{}, Enforce, "")
	h.Log = nil
	for _, c := range loadCases {
		b.Run(c.name, func(b *testing.B) {
			b.SetBytes(int64(len(c.body)))
			for i := 0; i < b.N; i++ {
				serve(h, c.body)
			}
		})
	}
}

// TestConcurrentDecisions sends a mixed load from many goroutines, as an API
// server under load would, and checks every decision and the latency
// distribution. The bound is far below the webhook's 5 s timeout so that a
// performance regression fails here rather than in a cluster.
func TestConcurrentDecisions(t *testing.T) {
	if testing.Short() {
		t.Skip("load test")
	}
	h := handler(t, Enforce, "")
	h.Log = nil
	workers, perWorker := 32, 40
	if raceEnabled {
		workers, perWorker = 8, 8
	}
	var mu sync.Mutex
	var lat []time.Duration
	var wg sync.WaitGroup
	errs := make(chan string, workers*perWorker)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				c := loadCases[(w+i)%len(loadCases)]
				start := time.Now()
				rec := serve(h, c.body)
				d := time.Since(start)
				allowed := strings.Contains(rec.Body.String(), `"allowed":true`)
				if rec.Code != http.StatusOK || allowed != c.allowed {
					errs <- fmt.Sprintf("%s: code %d allowed %v", c.name, rec.Code, allowed)
				}
				mu.Lock()
				lat = append(lat, d)
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p50, p99, max := lat[len(lat)/2], lat[len(lat)*99/100], lat[len(lat)-1]
	t.Logf("%d requests from %d workers: p50 %s, p99 %s, max %s", len(lat), workers, p50, p99, max)
	// The bound is for the webhook as deployed: the Linux container image.
	// Shared macOS and Windows CI runners are slower and noisier; the
	// correctness checks above still run there.
	if !raceEnabled && runtime.GOOS == "linux" && p99 > 2*time.Second {
		t.Errorf("p99 latency %s is too close to the webhook's 5 s timeout", p99)
	}
}
