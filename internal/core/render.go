package core

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// renderBudget bounds, in bytes of output, every rendered identifier and every list in a reason
// (allowed repositories, allowed branches, grants), so no request or policy can make a message
// large.
const renderBudget = 1024

// printable is the one renderer for identifiers that come from a request or from policy input:
// every one goes through it before it is formatted into a reason or an error. See render.
func printable(s string) string {
	return render(s, renderBudget)
}

// render returns s as is when s is valid UTF-8 made only of printable characters and fits in
// budget bytes, and quoted in Go syntax (ASCII only) otherwise, so identifiers cannot add lines,
// terminal controls or invisible characters (bidi overrides, zero-width spaces, line separators).
// A quoted s that does not fit is cut after a whole character or escape and followed by its
// length, `"abc"... (4194304 bytes)`, so the result never exceeds budget. budget must leave room
// for that suffix: 40 bytes are enough.
func render(s string, budget int) string {
	if len(s) <= budget && s != "" && utf8.ValidString(s) && !strings.ContainsFunc(s, func(c rune) bool { return !unicode.IsPrint(c) }) {
		return s
	}
	// A quoted string is at least two bytes longer than s, so a longer s is never quoted whole.
	if len(s)+2 <= budget {
		if q := strconv.QuoteToASCII(s); len(q) <= budget {
			return q
		}
	}
	suffix := fmt.Sprintf(`"... (%d bytes)`, len(s))
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); {
		_, n := utf8.DecodeRuneInString(s[i:])
		q := strconv.QuoteToASCII(s[i : i+n])
		q = q[1 : len(q)-1]
		if b.Len()+len(q)+len(suffix) > budget {
			break
		}
		b.WriteString(q)
		i += n
	}
	b.WriteString(suffix)
	return b.String()
}

// boundedList joins items, each rendered, within renderBudget bytes, the omission suffix included:
// the items that do not fit are counted as "and N more". The first item is always shown, cut if
// needed. No items read as "none".
func boundedList(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	// more is the suffix when the items after i are left out; each item leaves room for it.
	more := func(i int) string {
		if i == len(items)-1 {
			return ""
		}
		return fmt.Sprintf(" and %d more", len(items)-1-i)
	}
	var b strings.Builder
	b.WriteString(render(items[0], renderBudget-len(more(0))))
	for i := 1; i < len(items); i++ {
		item := printable(items[i])
		if b.Len()+len(", ")+len(item)+len(more(i)) > renderBudget {
			b.WriteString(more(i - 1))
			break
		}
		b.WriteString(", ")
		b.WriteString(item)
	}
	return b.String()
}
