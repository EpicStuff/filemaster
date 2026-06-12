//go:build linux

package fileaccess

import (
	"reflect"
	"sort"
	"testing"
)

func TestNormalizeWatchPaths(t *testing.T) {
	got := normalizeWatchPaths([]string{
		"/a",
		" /b ",
		"",
		"  ",
		"/a", // duplicate -> deduped
	})
	want := map[string]struct{}{"/a": {}, "/b": {}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalize = %v, want %v", got, want)
	}
}

func TestDiffWatchPaths(t *testing.T) {
	cases := []struct {
		name     string
		current  []string
		want     []string
		wantAdd  []string
		wantDrop []string
	}{
		{
			name:    "first run -- everything added",
			current: nil,
			want:    []string{"/a", "/b"},
			wantAdd: []string{"/a", "/b"},
		},
		{
			name:    "identical -- no diff",
			current: []string{"/a", "/b"},
			want:    []string{"/a", "/b"},
		},
		{
			name:     "full swap",
			current:  []string{"/a", "/b"},
			want:     []string{"/c", "/d"},
			wantAdd:  []string{"/c", "/d"},
			wantDrop: []string{"/a", "/b"},
		},
		{
			name:     "shrink",
			current:  []string{"/a", "/b", "/c"},
			want:     []string{"/a"},
			wantDrop: []string{"/b", "/c"},
		},
		{
			name:    "grow",
			current: []string{"/a"},
			want:    []string{"/a", "/b", "/c"},
			wantAdd: []string{"/b", "/c"},
		},
		{
			name:     "overlap",
			current:  []string{"/a", "/b"},
			want:     []string{"/b", "/c"},
			wantAdd:  []string{"/c"},
			wantDrop: []string{"/a"},
		},
	}
	toSet := func(s []string) map[string]struct{} {
		out := make(map[string]struct{}, len(s))
		for _, x := range s {
			out[x] = struct{}{}
		}
		return out
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			toAdd, toDrop := diffWatchPaths(toSet(c.current), toSet(c.want))
			sort.Strings(toAdd)
			sort.Strings(toDrop)
			if !reflect.DeepEqual(toAdd, sortedOrNil(c.wantAdd)) {
				t.Errorf("toAdd = %v, want %v", toAdd, c.wantAdd)
			}
			if !reflect.DeepEqual(toDrop, sortedOrNil(c.wantDrop)) {
				t.Errorf("toRemove = %v, want %v", toDrop, c.wantDrop)
			}
		})
	}
}

func sortedOrNil(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}
