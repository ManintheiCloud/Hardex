//go:build race

package admission

// raceEnabled: the race detector slows code ~10-20x, so latency bounds do
// not apply; concurrency correctness is still checked.
const raceEnabled = true
