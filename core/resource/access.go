package resource

// Helpers for reading values out of decoded JSON maps without panicking on
// missing or mistyped fields. Rules should use these rather than raw type
// assertions so that malformed input degrades into "field absent" instead of
// a crash.

// Lookup walks a path of map keys and returns the value found, if any.
func Lookup(m map[string]any, path ...string) (any, bool) {
	var cur any = m
	for _, key := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = mm[key]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// Map returns the map at path, or nil.
func Map(m map[string]any, path ...string) map[string]any {
	v, _ := Lookup(m, path...)
	mm, _ := v.(map[string]any)
	return mm
}

// Slice returns the slice at path, or nil.
func Slice(m map[string]any, path ...string) []any {
	v, _ := Lookup(m, path...)
	s, _ := v.([]any)
	return s
}

// Maps returns the elements of the slice at path that are maps.
func Maps(m map[string]any, path ...string) []map[string]any {
	var out []map[string]any
	for _, v := range Slice(m, path...) {
		if mm, ok := v.(map[string]any); ok {
			out = append(out, mm)
		}
	}
	return out
}

// String returns the string at path, or "".
func String(m map[string]any, path ...string) string {
	v, _ := Lookup(m, path...)
	s, _ := v.(string)
	return s
}

// Strings returns the string elements of the slice at path.
func Strings(m map[string]any, path ...string) []string {
	var out []string
	for _, v := range Slice(m, path...) {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Bool returns the boolean at path and whether it was present as a boolean.
func Bool(m map[string]any, path ...string) (value bool, set bool) {
	v, ok := Lookup(m, path...)
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

// Number returns the numeric value at path and whether it was present.
func Number(m map[string]any, path ...string) (float64, bool) {
	v, ok := Lookup(m, path...)
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}
