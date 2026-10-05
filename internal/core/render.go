package core

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// guidanceBudget bounds the lists in reasons (allowed repositories, allowed branches, grants), so
// no policy can make a message large.
const guidanceBudget = 1024

// printable is the one renderer for identifiers that come from a request or from policy input:
// every one goes through it before it is formatted into a reason or an error. It returns s as is
// when s is valid UTF-8 made only of printable characters, and quoted in Go syntax (ASCII only)
// otherwise, so identifiers cannot add lines, terminal controls or invisible characters (bidi
// overrides, zero-width spaces, line separators). Beyond MaxRefNameLen bytes it is cut, so a huge
// identifier cannot make a huge message.
func printable(s string) string {
	if len(s) > MaxRefNameLen {
		return strconv.QuoteToASCII(s[:MaxRefNameLen]) + fmt.Sprintf("... (%d bytes)", len(s))
	}
	if s != "" && utf8.ValidString(s) && !strings.ContainsFunc(s, func(c rune) bool { return !unicode.IsPrint(c) }) {
		return s
	}
	return strconv.QuoteToASCII(s)
}

// boundedList joins items, each through printable, within guidanceBudget bytes; the items that do
// not fit are counted as "and N more". The first item is always shown. No items read as "none".
func boundedList(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	var b strings.Builder
	for i, item := range items {
		item = printable(item)
		if i > 0 && b.Len()+len(", ")+len(item) > guidanceBudget {
			fmt.Fprintf(&b, " and %d more", len(items)-i)
			break
		}
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(item)
	}
	return b.String()
}
