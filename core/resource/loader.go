package resource

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ManintheiCloud/Hardex/internal/yamlsafe"
)

// MaxInputBytes bounds the size of any single input file or stream. Hardex
// treats its input as untrusted: a manifest repository may be attacker
// controlled, so unbounded reads are not acceptable.
const MaxInputBytes = 32 << 20 // 32 MiB

// Load reads Kubernetes objects from the given paths. A path may be a file,
// a directory (walked recursively for .yaml, .yml and .json files), or "-"
// for standard input. Objects of kind "List" (as produced by
// `kubectl get -o yaml`) are expanded into their items.
func Load(paths []string, stdin io.Reader) (*Inventory, error) {
	inv := NewInventory()
	for _, p := range paths {
		if p == "-" {
			if err := loadStream(inv, io.LimitReader(stdin, MaxInputBytes+1), "<stdin>"); err != nil {
				return nil, err
			}
			continue
		}
		files, err := expand(p)
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if err := loadFile(inv, f); err != nil {
				return nil, err
			}
		}
	}
	return inv, nil
}

func expand(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{path}, nil
	}
	var files []string
	err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != path && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		// Do not follow symlinks out of the tree being scanned.
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".yaml", ".yml", ".json":
			files = append(files, p)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}

func loadFile(inv *Inventory, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return loadStream(inv, io.LimitReader(f, MaxInputBytes+1), path)
}

func loadStream(inv *Inventory, r io.Reader, source string) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("%s: %w", source, err)
	}
	if len(data) > MaxInputBytes {
		return fmt.Errorf("%s: input exceeds %d bytes", source, MaxInputBytes)
	}
	inv.Sources = append(inv.Sources, source)
	for _, doc := range splitDocuments(data) {
		if err := decodeDocument(inv, doc, source); err != nil {
			return err
		}
	}
	return nil
}

type document struct {
	body []byte
	line int
}

// splitDocuments splits a multi-document YAML stream on "---" separators,
// recording the starting line of each document for precise reporting.
func splitDocuments(data []byte) []document {
	var docs []document
	var cur bytes.Buffer
	start, lineNo := 1, 0
	flush := func() {
		if hasContent(cur.Bytes()) {
			docs = append(docs, document{body: append([]byte(nil), cur.Bytes()...), line: start})
		}
		cur.Reset()
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), MaxInputBytes)
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if line == "---" || strings.HasPrefix(line, "--- ") || strings.HasPrefix(line, "---\t") {
			flush()
			start = lineNo + 1
			continue
		}
		if line == "..." {
			continue
		}
		if t := strings.TrimSpace(line); cur.Len() == 0 && (t == "" || strings.HasPrefix(t, "#")) {
			// Leading blank and comment lines are not part of the object;
			// skipping them makes reported line numbers point at the object.
			start = lineNo + 1
			continue
		}
		cur.WriteString(line)
		cur.WriteByte('\n')
	}
	flush()
	return docs
}

func hasContent(b []byte) bool {
	for _, line := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(line)
		if t != "" && !strings.HasPrefix(t, "#") {
			return true
		}
	}
	return false
}

func decodeDocument(inv *Inventory, doc document, source string) error {
	file, err := yamlsafe.Parse(doc.body)
	if err != nil {
		return fmt.Errorf("%s:%d: invalid YAML: %v", source, doc.line, firstLine(err.Error()))
	}
	if err := checkAliasExpansion(file); err != nil {
		return fmt.Errorf("%s:%d: %w", source, doc.line, err)
	}
	for _, d := range file.Docs {
		if d.Body == nil {
			continue
		}
		body := normalizeYAML11(d.Body)
		var raw any
		if err := yamlsafe.NodeToValue(body, &raw); err != nil {
			return fmt.Errorf("%s:%d: invalid YAML: %v", source, doc.line, firstLine(err.Error()))
		}
		// Round-trip through JSON so every number is a float64 and every
		// map is map[string]any, exactly as the accessors expect.
		js, err := json.Marshal(jsonCompatible(raw))
		if err != nil {
			return fmt.Errorf("%s:%d: %v", source, doc.line, err)
		}
		var v any
		if err := json.Unmarshal(js, &v); err != nil {
			return fmt.Errorf("%s:%d: %v", source, doc.line, err)
		}
		if v == nil {
			continue
		}
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("%s:%d: document is not a mapping", source, doc.line)
		}
		if err := addDecoded(inv, m, source, doc.line); err != nil {
			return err
		}
	}
	return nil
}

// jsonCompatible converts map[any]any (non-string keys) into
// map[string]any so that the value can be encoded as JSON.
func jsonCompatible(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			t[k] = jsonCompatible(val)
		}
		return t
	case map[any]any:
		m := make(map[string]any, len(t))
		for k, val := range t {
			m[fmt.Sprint(k)] = jsonCompatible(val)
		}
		return m
	case []any:
		for i := range t {
			t[i] = jsonCompatible(t[i])
		}
		return t
	}
	return v
}

func addDecoded(inv *Inventory, m map[string]any, source string, line int) error {
	if kind := String(m, "kind"); strings.HasSuffix(kind, "List") && m["items"] != nil {
		for _, item := range Maps(m, "items") {
			if err := addDecoded(inv, item, source, line); err != nil {
				return err
			}
		}
		return nil
	}
	obj, err := NewObject(m, source, line)
	if err != nil {
		// A document without a kind is not a Kubernetes object (e.g. a Helm
		// values file that matched *.yaml). Record it rather than failing the
		// whole assessment, so the omission is visible in the report.
		inv.Skipped = append(inv.Skipped, fmt.Sprintf("%s:%d: no kind; not a Kubernetes object", source, line))
		return nil
	}
	inv.Add(obj)
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
