package main

import (
	"testing"

	apiclient "github.com/safing/portmaster/base/api/client"
	"github.com/safing/structures/dsd"
)

func TestPromptIdentityFromMessage(t *testing.T) {
	payload := struct {
		EventData struct {
			Profile struct {
				ID         string
				Source     string
				Name       string
				LinkedPath string
			}
			Subject struct {
				Exe string
				Op  string
			}
		}
	}{}
	payload.EventData.Profile.ID = "PTstable"
	payload.EventData.Profile.Source = "local"
	payload.EventData.Profile.Name = "Stable Helper"
	payload.EventData.Profile.LinkedPath = "/tmp/stable-helper"
	payload.EventData.Subject.Exe = "/tmp/stable-helper"
	payload.EventData.Subject.Op = "open"
	raw, err := dsd.Dump(payload, dsd.JSON)
	if err != nil {
		t.Fatalf("Dump: %v", err)
	}

	got, err := promptIdentityFromMessage(&apiclient.Message{Key: "notifications:all/fileaccess:local/PTstable:open:/tmp/probe", RawValue: raw})
	if err != nil {
		t.Fatalf("promptIdentityFromMessage: %v", err)
	}
	if got.Key == "" || got.Identity.ProfileSource != "local" || got.Identity.ProfileID != "PTstable" || got.Identity.Executable != "/tmp/stable-helper" || got.Identity.Operation != "open" {
		t.Fatalf("identity = %#v, want stable prompt identity", got)
	}
}
