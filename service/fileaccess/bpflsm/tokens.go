//go:build linux

package bpflsm

import (
	"path/filepath"
	"unicode/utf8"
)

// A pattern is tokenized here, in Go, where pattern parsing (scanChunk, getEsc,
// class syntax, bad-pattern detection) is static. The kernel then executes only
// Go's Match/matchChunk control flow over the flat token program. refMatch runs
// that same control flow in Go and is proven against filepath.Match, so the
// tokenization is tested independently of the kernel interpreter.

// tokKind is a token's kind within a chunk.
type tokKind uint8

const (
	tokLiteral  tokKind = 0
	tokQuestion tokKind = 1
	tokClass    tokKind = 2
)

// runeRange is one lo..hi class range (inclusive), as getEsc resolves it.
type runeRange struct {
	Lo rune
	Hi rune
}

// token is one element of a chunk: a literal byte, a '?', or a '[...]' class.
type token struct {
	Kind    tokKind
	Byte    byte
	Negated bool
	Ranges  []runeRange
}

// chunk is a maximal run of tokens between stars; Star is set when at least one
// '*' preceded it (scanChunk's star return).
type chunk struct {
	Star   bool
	Tokens []token
}

// tokenProgram is a pattern's full tokenization: its ordered chunks.
type tokenProgram struct {
	Chunks []chunk
}

// tokenize parses pattern into a tokenProgram, mirroring Go's scanChunk and the
// class syntax of matchChunk/getEsc. ok is false for an ErrBadPattern pattern
// (exactly the patterns filepath.Match rejects), so the caller leaves it out of
// the kernel tables, as the engine never matches such a rule.
func tokenize(pattern string) (tokenProgram, bool) {
	var program tokenProgram
	for len(pattern) > 0 {
		var star bool
		var raw string
		star, raw, pattern = scanChunk(pattern)
		// A pattern whose chunk is malformed is ErrBadPattern in filepath.Match.
		if _, _, err := matchChunk(raw, ""); err != nil {
			return tokenProgram{}, false
		}
		tokens, ok := tokenizeChunk(raw)
		if !ok {
			return tokenProgram{}, false
		}
		program.Chunks = append(program.Chunks, chunk{Star: star, Tokens: tokens})
	}
	return program, true
}

// tokenizeChunk turns one scanChunk chunk into tokens. It consumes the chunk
// exactly as matchChunk does: '[' class with '^' and getEsc ranges, '?', '\'
// escape, or a literal byte.
func tokenizeChunk(c string) ([]token, bool) {
	var tokens []token
	for len(c) > 0 {
		switch c[0] {
		case '[':
			c = c[1:]
			negated := false
			if len(c) > 0 && c[0] == '^' {
				negated = true
				c = c[1:]
			}
			var ranges []runeRange
			nrange := 0
			for {
				if len(c) > 0 && c[0] == ']' && nrange > 0 {
					c = c[1:]
					break
				}
				var lo, hi rune
				var err error
				if lo, c, err = getEsc(c); err != nil {
					return nil, false
				}
				hi = lo
				if c[0] == '-' {
					if hi, c, err = getEsc(c[1:]); err != nil {
						return nil, false
					}
				}
				ranges = append(ranges, runeRange{Lo: lo, Hi: hi})
				nrange++
			}
			tokens = append(tokens, token{Kind: tokClass, Negated: negated, Ranges: ranges})
		case '?':
			tokens = append(tokens, token{Kind: tokQuestion})
			c = c[1:]
		case '\\':
			c = c[1:]
			if len(c) == 0 {
				return nil, false
			}
			tokens = append(tokens, token{Kind: tokLiteral, Byte: c[0]})
			c = c[1:]
		default:
			tokens = append(tokens, token{Kind: tokLiteral, Byte: c[0]})
			c = c[1:]
		}
	}
	return tokens, true
}

// refMatch runs Go's Match/matchChunk control flow over a token program. It is
// the Go reference for the kernel interpreter and is tested against
// filepath.Match. It returns whether name matches, with the engine's semantics:
// a star never skips '/', '?' never matches '/', and a class may match '/'.
func refMatch(program tokenProgram, name string) bool {
	chunks := program.Chunks
	for i := 0; i < len(chunks); i++ {
		star := chunks[i].Star
		tokens := chunks[i].Tokens
		last := i == len(chunks)-1
		if star && len(tokens) == 0 {
			// Trailing star: matches the rest unless it contains a separator.
			return !containsSeparator(name)
		}
		rest, ok := refMatchChunk(tokens, name)
		if ok && (len(rest) == 0 || !last) {
			name = rest
			continue
		}
		if star {
			matched := false
			for j := 0; j < len(name) && name[j] != '/'; j++ {
				rest, ok := refMatchChunk(tokens, name[j+1:])
				if ok {
					if last && len(rest) > 0 {
						continue
					}
					name = rest
					matched = true
					break
				}
			}
			if matched {
				continue
			}
		}
		return false
	}
	return len(name) == 0
}

// refMatchChunk is matchChunk over tokens, for an already-validated chunk.
func refMatchChunk(tokens []token, s string) (string, bool) {
	for _, tok := range tokens {
		if len(s) == 0 {
			return "", false
		}
		switch tok.Kind {
		case tokClass:
			r, n := utf8.DecodeRuneInString(s)
			s = s[n:]
			match := false
			for _, rng := range tok.Ranges {
				if rng.Lo <= r && r <= rng.Hi {
					match = true
				}
			}
			if match == tok.Negated {
				return "", false
			}
		case tokQuestion:
			if s[0] == '/' {
				return "", false
			}
			_, n := utf8.DecodeRuneInString(s)
			s = s[n:]
		default:
			if s[0] != tok.Byte {
				return "", false
			}
			s = s[1:]
		}
	}
	return s, true
}

func containsSeparator(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return true
		}
	}
	return false
}

var _ = filepath.Separator
