package mimicry

import (
	"regexp"
	"strings"
)

// Dateline steganography erasure.
//
// Real Claude Code, when it detects a NON-official base URL (a forwarding
// gateway sits in front of api.anthropic.com), encodes a 3-bit beacon into the
// "Today's date is YYYY-MM-DD." sentence it injects into the environment
// context (top-level system prompt on turn 1, <system-reminder> blocks on
// later turns). Verified byte-for-byte against the CC 2.1.197 standalone binary
// (functions rdp / odp / qla — see crack/cc2197/SPEC.md §6):
//
//	function rdp(){ if(vrt()) return null;            // official base URL → no beacon
//	  let e=host, n=(tz==="Asia/Shanghai"||tz==="Asia/Urumqi");
//	  return { known:<host in known-gateway list>, labKw:<host has lab keyword>, cnTZ:n } }
//	function odp(known,labKw){ 00→"'"(U+0027) 10→"’"(U+2019) 01→"ʼ"(U+02BC) 11→"ʹ"(U+02B9) }
//	function qla(d){ let t=rdp(); return `Today${odp(t.known,t.labKw)}s date is
//	                 ${t.cnTZ ? d.replaceAll("-","/") : d}.` }
//
// So the apostrophe code point leaks 2 bits (known-gateway, lab-keyword match
// on OUR host) and the date separator leaks 1 bit (client in a China timezone).
// Because our clients point Claude Code at a non-official host, that beacon
// rides every /v1/messages body straight to Anthropic and marks the request as
// proxied — exactly the third-party signal we suppress everywhere else.
//
// NormalizeDateline rewrites the sentence back to the canonical ASCII form real
// CC sends on the official endpoint (U+0027 apostrophe, "-" separator), erasing
// all three bits. Ported from Wei-Shaw/sub2api's anthropicfp.NormalizeDateline
// (commit 59e9356c).

// datelineHyphenRe / datelineSlashRe match the sentence with any of the four
// apostrophe code points and either separator. Two regexes (rather than one
// with a `[-/]` separator class) keep the two separators forced to AGREE —
// RE2 has no backreferences — so a mixed "2026-07/01" that shows up in user
// prose never matches. The hyphen form also matches the already-canonical
// sentence; the replacer makes that a no-op so canonical text is never touched.
var (
	datelineHyphenRe = regexp.MustCompile("Today['’ʼʹ]s date is ([0-9]{4})-([0-9]{2})-([0-9]{2})\\.")
	datelineSlashRe  = regexp.MustCompile("Today['’ʼʹ]s date is ([0-9]{4})/([0-9]{2})/([0-9]{2})\\.")
)

// NormalizeDateline scans an Anthropic /v1/messages request body and rewrites
// every fingerprinted dateline sentence back to canonical ASCII form. It is a
// byte-surgical transform: only the matched sentence bytes change, and when no
// non-canonical dateline is present the ORIGINAL slice is returned unchanged
// (byte-identical) with changed=false — so the fingerprint/cch signatures over
// untouched bodies are unaffected. No JSON reparse/remarshal, no new deps.
//
// Scope note vs sub2api: sub2api restricts the messages scan to the interior of
// <system-reminder> tags (to shield user prose) and does a JSON-field parse.
// We run whole-body but only ever REWRITE non-canonical forms (an exotic
// apostrophe, or a slash-separated date — neither of which appears in genuine
// user text), so the practical touch surface is identical while staying a pure
// byte edit that preserves everything else exactly.
func NormalizeDateline(body []byte) ([]byte, bool) {
	if len(body) == 0 {
		return body, false
	}
	s := string(body)
	// Cheap reject: the substring is present in every real CC dateline and
	// avoids the regex machinery on the vast majority of bodies.
	if !strings.Contains(s, "s date is ") {
		return body, false
	}

	changed := false
	canon := func(re *regexp.Regexp) func(string) string {
		return func(m string) string {
			sub := re.FindStringSubmatch(m)
			if sub == nil {
				return m
			}
			out := "Today's date is " + sub[1] + "-" + sub[2] + "-" + sub[3] + "."
			if out != m {
				changed = true
			}
			return out
		}
	}
	s = datelineHyphenRe.ReplaceAllStringFunc(s, canon(datelineHyphenRe))
	s = datelineSlashRe.ReplaceAllStringFunc(s, canon(datelineSlashRe))
	if !changed {
		return body, false
	}
	return []byte(s), true
}
