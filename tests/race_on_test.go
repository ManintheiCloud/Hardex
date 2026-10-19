//go:build race

package tests

// The race detector slows execution several-fold.
const raceEnabled = true
