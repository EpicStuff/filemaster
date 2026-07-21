package fileaccess

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	portapi "github.com/safing/portmaster/base/api"
	apiclient "github.com/safing/portmaster/base/api/client"
	"github.com/safing/portmaster/base/config"
	"github.com/safing/portmaster/base/database"
	"github.com/safing/portmaster/base/database/query"
	"github.com/safing/portmaster/base/notifications"
)

type promptWSTestInstance struct {
	cfg     *config.Config
	dataDir string
}

func (i *promptWSTestInstance) Config() *config.Config { return i.cfg }
func (i *promptWSTestInstance) DataDir() string        { return i.dataDir }
func (i *promptWSTestInstance) Ready() bool            { return true }
func (i *promptWSTestInstance) SetCmdLineOperation(func() error) {
}

func TestFileAccessPromptWebsocketRoundTrip(t *testing.T) {
	if err := database.Initialize(t.TempDir()); err != nil && err.Error() != "database already initialized" {
		t.Fatalf("database.Initialize: %v", err)
	}

	instance := &promptWSTestInstance{dataDir: t.TempDir()}
	cfg, err := config.New(instance)
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	instance.cfg = cfg

	notificationsModule, err := notifications.New(instance)
	if err != nil {
		t.Fatalf("notifications.New: %v", err)
	}
	if err := notificationsModule.Start(); err != nil {
		t.Fatalf("notifications.Start: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on test API port: %v", err)
	}
	apiAddress := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("close test listener: %v", err)
	}

	portapi.SetDefaultAPIListenAddress(apiAddress)
	apiModule, err := portapi.New(instance)
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	if err := portapi.SetAuthenticator(func(r *http.Request, s *http.Server) (*portapi.AuthToken, error) {
		return &portapi.AuthToken{Read: portapi.PermitSelf, Write: portapi.PermitSelf}, nil
	}); err != nil && !errors.Is(err, portapi.ErrAuthenticationAlreadySet) {
		t.Fatalf("api.SetAuthenticator: %v", err)
	}
	if err := apiModule.Start(); err != nil {
		t.Fatalf("api.Start: %v", err)
	}
	defer apiModule.Stop()

	client := apiclient.NewClient(apiAddress)
	defer client.Shutdown()
	go client.StayConnected()

	select {
	case <-client.Online():
	case <-time.After(3 * time.Second):
		t.Fatal("API client did not connect")
	}

	messages := make(chan *apiclient.Message, 10)
	client.Qsub(query.New("notifications:all/").Print(), func(msg *apiclient.Message) {
		messages <- msg
	})

	for {
		select {
		case msg := <-messages:
			switch msg.Type {
			case apiclient.MsgDone:
				goto qsubReady
			case apiclient.MsgError, apiclient.MsgWarning:
				t.Fatalf("notification qsub returned %s: %s", msg.Type, msg.Key)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("notification qsub did not become ready")
		}
	}

qsubReady:

	event := FileEvent{
		PID:  1234,
		Exe:  "/usr/bin/cat",
		Path: "/tmp/filemaster-test/ws-secret.txt",
		Op:   OpOpen,
	}
	source := newFakeSource([]FileEvent{event})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- source.Run(ctx, decisionPendingHandler{handler: NewPromptHandler(&NotificationsPrompter{}, nil, 3*time.Second)})
	}()

	var promptKey string
waitForPrompt:
	for {
		select {
		case msg := <-messages:
			if msg.Type == apiclient.MsgError || msg.Type == apiclient.MsgWarning {
				t.Fatalf("notification qsub returned %s: %s", msg.Type, msg.Key)
			}
			if msg.Type != apiclient.MsgNew || !strings.HasPrefix(msg.Key, "notifications:all/fileaccess:open:") {
				continue
			}
			if !strings.Contains(string(msg.RawValue), event.Path) || !strings.Contains(string(msg.RawValue), event.Exe) {
				t.Fatalf("prompt payload for %s does not contain event path/exe", msg.Key)
			}
			promptKey = msg.Key
			break waitForPrompt
		case <-time.After(3 * time.Second):
			t.Fatal("did not receive file-access prompt over websocket qsub")
		}
	}

	updates := make(chan *apiclient.Message, 2)
	client.Update(promptKey, map[string]string{"SelectedActionID": ActionAllow}, func(msg *apiclient.Message) {
		updates <- msg
	})
	select {
	case msg := <-updates:
		if msg.Type != apiclient.MsgSuccess {
			t.Fatalf("prompt update returned %s %s, want success", msg.Type, msg.Key)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("prompt update did not complete")
	}

	verdictDeadline := time.After(3 * time.Second)
	for {
		select {
		case <-verdictDeadline:
			t.Fatal("fake source did not receive allow verdict")
		default:
			decisions := source.Decisions()
			if len(decisions) == 0 {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			if decisions[0].Event != event || decisions[0].Verdict != VerdictAllow {
				t.Fatalf("decision = %+v, want allow for original event", decisions[0])
			}
			if err := source.Close(); err != nil {
				t.Fatalf("source.Close: %v", err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("source.Run: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("source.Run did not stop")
			}
			return
		}
	}
}
