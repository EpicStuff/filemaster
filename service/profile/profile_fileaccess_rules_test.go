package profile

import (
	"reflect"
	"testing"
)

func TestCoalesceFileAccessRuleEntriesUsesEffectivePrecedence(t *testing.T) {
	tests := []struct {
		name  string
		list  []string
		entry string
		want  []string
	}{
		{
			name:  "failed mutation with unrelated prepend saves without duplicate",
			list:  []string{"+ /tmp/unrelated", "+ /tmp/file"},
			entry: "+ /tmp/file",
			want:  []string{"+ /tmp/unrelated", "+ /tmp/file"},
		},
		{
			name:  "opposing exact rule requires new leading decision",
			list:  []string{"- /tmp/file", "+ /tmp/file", "+ /tmp/unrelated"},
			entry: "+ /tmp/file",
			want:  []string{"+ /tmp/file", "+ /tmp/unrelated"},
		},
		{
			name:  "broader first match requires new leading exact decision",
			list:  []string{"+ /tmp/*", "+ /tmp/file", "- /tmp/unrelated"},
			entry: "+ /tmp/file",
			want:  []string{"+ /tmp/file", "+ /tmp/*", "- /tmp/unrelated"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := coalesceFileAccessRuleEntries(test.list, test.entry)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("coalesced entries = %v, want %v", got, test.want)
			}
		})
	}
}
