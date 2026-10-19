// Package history stores assessment reports over time and derives trends
// and drift from them.
//
// A history is a directory of JSON reports, one per assessment, named by
// UTC timestamp so that the directory listing is the timeline. Files are
// written atomically and readable only by their owner (reports describe
// weaknesses in the assessed environment).
package history

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/verification"
)

// Store is a directory of reports.
type Store struct {
	dir string
}

// Open creates the directory if needed.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, fmt.Errorf("history directory is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

// Dir returns the store's directory.
func (s *Store) Dir() string { return s.dir }

const suffix = ".hardex.json"

// Save writes a report and returns its path.
func (s *Store) Save(r *finding.Report) (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	base := r.GeneratedAt.UTC().Format("20060102T150405Z")
	var path string
	for i := 0; ; i++ {
		name := base
		if i > 0 {
			name = fmt.Sprintf("%s-%d", base, i)
		}
		path = filepath.Join(s.dir, name+suffix)
		f, err := os.OpenFile(path+".tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		if _, err := os.Stat(path); err == nil {
			f.Close()
			os.Remove(path + ".tmp")
			continue
		}
		if _, err = f.Write(data); err == nil {
			err = f.Sync()
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(path + ".tmp")
			return "", err
		}
		return path, os.Rename(path+".tmp", path)
	}
}

// Entry is one stored report.
type Entry struct {
	Path   string
	Report *finding.Report
}

// List returns stored reports, oldest first. Files that are not valid
// reports are skipped and named in the returned warnings.
func (s *Store) List() ([]Entry, []string, error) {
	names, err := filepath.Glob(filepath.Join(s.dir, "*"+suffix))
	if err != nil {
		return nil, nil, err
	}
	var entries []Entry
	var warnings []string
	for _, p := range names {
		f, err := os.Open(p)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", p, err))
			continue
		}
		r, err := finding.ReadReport(f)
		f.Close()
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", p, err))
			continue
		}
		entries = append(entries, Entry{Path: p, Report: r})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i].Report.GeneratedAt, entries[j].Report.GeneratedAt
		if !a.Equal(b) {
			return a.Before(b)
		}
		return seq(entries[i].Path) < seq(entries[j].Path)
	})
	return entries, warnings, nil
}

// seq returns the collision counter in a report file name
// ("20261019T120000Z-2.hardex.json" → 2), so reports saved within the same
// second keep their order.
func seq(path string) int {
	name := strings.TrimSuffix(filepath.Base(path), suffix)
	if i := strings.LastIndexByte(name, '-'); i >= 0 {
		if n, err := strconv.Atoi(name[i+1:]); err == nil {
			return n
		}
	}
	return 0
}

// Latest returns the most recent report, or nil if the store is empty.
func (s *Store) Latest() (*Entry, error) {
	entries, _, err := s.List()
	if err != nil || len(entries) == 0 {
		return nil, err
	}
	return &entries[len(entries)-1], nil
}

// Prune keeps only the newest keep reports.
func (s *Store) Prune(keep int) (int, error) {
	if keep <= 0 {
		return 0, nil
	}
	entries, _, err := s.List()
	if err != nil {
		return 0, err
	}
	removed := 0
	for i := 0; i < len(entries)-keep; i++ {
		if !strings.HasPrefix(filepath.Clean(entries[i].Path), filepath.Clean(s.dir)) {
			continue
		}
		if err := os.Remove(entries[i].Path); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

// Point is one assessment in a trend.
type Point struct {
	Time     time.Time       `json:"time"`
	Profile  string          `json:"profile"`
	Inputs   []string        `json:"inputs"`
	Summary  finding.Summary `json:"summary"`
	Complete bool            `json:"complete"`
	// Introduced and Resolved are relative to the previous point.
	Introduced int      `json:"introduced"`
	Resolved   int      `json:"resolved"`
	Unverified int      `json:"unverified"`
	Caveats    []string `json:"caveats,omitempty"`
}

// Trend summarises a sequence of reports.
func Trend(entries []Entry) []Point {
	points := make([]Point, len(entries))
	for i, e := range entries {
		r := e.Report
		points[i] = Point{Time: r.GeneratedAt, Profile: r.Profile, Inputs: r.Inputs, Summary: r.Summary, Complete: r.Complete()}
		if i > 0 {
			c := verification.Compare(entries[i-1].Report, r)
			points[i].Introduced, points[i].Resolved, points[i].Unverified = len(c.Introduced), len(c.Resolved), len(c.Unverified)
			points[i].Caveats = c.Caveats
			if strings.Join(entries[i-1].Report.Inputs, "\x00") != strings.Join(r.Inputs, "\x00") {
				points[i].Caveats = append(points[i].Caveats, "inputs differ from the previous assessment")
			}
		}
	}
	return points
}
