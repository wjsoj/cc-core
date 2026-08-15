package mimicry

// Minimal top-level JSON scanning, used by the Codex frame rewriter.
//
// This exists so a rewrite can address a SPECIFIC top-level key instead of
// searching the whole document for a `"key":"` literal. The difference is not
// cosmetic: a Codex frame embeds arbitrary user prose (prompts, tool output,
// file contents), so any literal search can and eventually will match inside
// content the proxy has no business touching.
//
// Nothing here validates the document. A malformed frame simply stops the scan,
// and every caller treats "not found" as "leave it alone".

// isJSONSpace lives in cachecontrol.go — same package, same definition.

func skipJSONSpace(b []byte, i int) int {
	for i < len(b) && isJSONSpace(b[i]) {
		i++
	}
	return i
}

// jsonStringEnd returns the index just past the closing quote of the string
// starting at b[i] (which must be '"'), honouring backslash escapes.
func jsonStringEnd(b []byte, i int) (int, bool) {
	if i >= len(b) || b[i] != '"' {
		return 0, false
	}
	esc := false
	for j := i + 1; j < len(b); j++ {
		switch {
		case esc:
			esc = false
		case b[j] == '\\':
			esc = true
		case b[j] == '"':
			return j + 1, true
		}
	}
	return 0, false
}

// jsonValueEnd returns the index just past the value starting at b[i].
func jsonValueEnd(b []byte, i int) (int, bool) {
	if i >= len(b) {
		return 0, false
	}
	switch b[i] {
	case '"':
		return jsonStringEnd(b, i)
	case '{':
		return matchBrace(b, i)
	case '[':
		return matchBracket(b, i)
	}
	// Number, true, false, null — runs until a structural byte.
	for j := i; j < len(b); j++ {
		switch b[j] {
		case ',', '}', ']', ' ', '\t', '\n', '\r':
			if j == i {
				return 0, false
			}
			return j, true
		}
	}
	return len(b), true
}

// scanTopLevelObject walks the key/value pairs of the top-level object in b,
// calling visit with each key and the byte span of its value. Returning false
// from visit stops the walk.
func scanTopLevelObject(b []byte, visit func(key string, valStart, valEnd int) bool) {
	i := skipJSONSpace(b, 0)
	if i >= len(b) || b[i] != '{' {
		return
	}
	i++
	for {
		i = skipJSONSpace(b, i)
		if i >= len(b) || b[i] == '}' {
			return
		}
		if b[i] != '"' {
			return
		}
		keyEnd, ok := jsonStringEnd(b, i)
		if !ok {
			return
		}
		key := string(b[i+1 : keyEnd-1])
		i = skipJSONSpace(b, keyEnd)
		if i >= len(b) || b[i] != ':' {
			return
		}
		i = skipJSONSpace(b, i+1)
		valEnd, ok := jsonValueEnd(b, i)
		if !ok {
			return
		}
		if !visit(key, i, valEnd) {
			return
		}
		i = skipJSONSpace(b, valEnd)
		if i < len(b) && b[i] == ',' {
			i++
			continue
		}
		return
	}
}

// topLevelValueSpan returns the byte span of one top-level key's value.
func topLevelValueSpan(b []byte, key string) (int, int, bool) {
	var start, end int
	found := false
	scanTopLevelObject(b, func(k string, vs, ve int) bool {
		if k != key {
			return true
		}
		start, end, found = vs, ve, true
		return false
	})
	return start, end, found
}

// matchBracket is matchBrace for arrays.
func matchBracket(b []byte, start int) (int, bool) {
	return matchDelim(b, start, '[', ']')
}

func matchDelim(b []byte, start int, open, close byte) (int, bool) {
	if start >= len(b) || b[start] != open {
		return 0, false
	}
	depth := 0
	inStr := false
	esc := false
	for i := start; i < len(b); i++ {
		c := b[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case open:
			depth++
		case close:
			depth--
			if depth == 0 {
				return i + 1, true
			}
		}
	}
	return 0, false
}

// replaceSpan splices repl in place of b[start:end], returning a new slice.
func replaceSpan(b []byte, start, end int, repl []byte) []byte {
	out := make([]byte, 0, len(b)-(end-start)+len(repl))
	out = append(out, b[:start]...)
	out = append(out, repl...)
	out = append(out, b[end:]...)
	return out
}

// looksLikeUUID reports whether s is a canonical 36-character hyphenated UUID.
//
// The Codex frame rewriter substitutes identity values as literal tokens across
// the whole frame, which is only safe for values long and structured enough
// that they cannot occur incidentally. Every id in the captures is a UUID; a
// downstream client is free to send something else, and a one-character
// "session id" would otherwise rewrite every occurrence of that character in
// the frame — including JSON syntax and user prose.
func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}
