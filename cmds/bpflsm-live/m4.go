package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type m4Record struct {
	Path     string `json:"path"`
	DestPath string `json:"dest_path"`
	Op       string `json:"op"`
	Verdict  string `json:"verdict"`
	Profile  string `json:"profile"`
	AppName  string `json:"app_name"`
}

type m4Notice struct {
	Key              string
	Type             uint8  `json:"Type"`
	Title            string `json:"Title"`
	Message          string `json:"Message"`
	SelectedActionID string `json:"SelectedActionID"`
	AvailableActions []struct {
		ID   string `json:"ID"`
		Text string `json:"Text"`
	} `json:"AvailableActions"`
}

func m4Helper(args []string) error {
	if len(args) == 0 {
		return errors.New("missing M4 helper operation")
	}
	switch args[0] {
	case "noop":
		time.Sleep(300 * time.Millisecond)
		return nil
	case "delete":
		if len(args) == 2 {
			return os.Remove(args[1])
		}
	case "create":
		if len(args) == 2 {
			return os.Mkdir(args[1], 0o755)
		}
	case "rename":
		if len(args) == 3 {
			return os.Rename(args[1], args[2])
		}
	case "link":
		if len(args) == 3 {
			return os.Link(args[1], args[2])
		}
	case "burst":
		if len(args) == 2 {
			for i := 0; i < 10000; i++ {
				if err := os.Remove(filepath.Join(args[1], fmt.Sprintf("burst-%05d", i))); err != nil {
					return fmt.Errorf("burst delete %d: %w", i, err)
				}
			}
			return nil
		}
	}
	return fmt.Errorf("invalid M4 helper arguments: %v", args)
}

func m4Matrix() {
	fmt.Println("== M4: decision records, deny notice and volume suppressor ==")
	base := filepath.Join(*scope, "m4")
	must(os.MkdirAll(base, 0o755))
	self, err := os.Executable()
	must(err)
	allowExe := filepath.Join(*outside, "m4-allow-helper")
	denyExe := filepath.Join(*outside, "m4-deny-helper")
	for _, target := range []string{allowExe, denyExe} {
		in, err := os.Open(self)
		must(err)
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		must(err)
		_, err = io.Copy(out, in)
		must(err)
		must(in.Close())
		must(out.Close())
	}
	must(startDaemon("off"))
	allowName, denyName := "M4 allowed app", "M4 denied app"
	allowFP := []map[string]string{{"Type": "path", "Operation": "equals", "Value": allowExe}}
	denyFP := []map[string]string{{"Type": "path", "Operation": "equals", "Value": denyExe}}
	putProfile(allowName, allowFP, map[string]any{"fileaccess": map[string]any{"writeRules": []string{"+ " + *scope + "/**"}}})
	putProfile(denyName, denyFP, map[string]any{"filter": map[string]any{"defaultAction": "block"}})
	must(setMode("enforce"))
	report(m4Run(allowExe, "noop"), "allow helper learned")
	report(m4Run(denyExe, "noop"), "deny helper learned")

	for _, tc := range []struct {
		op   string
		args func(string) []string
	}{
		{"delete", func(prefix string) []string { return []string{prefix + "-source"} }},
		{"create", func(prefix string) []string { return []string{prefix + "-directory"} }},
		{"rename", func(prefix string) []string { return []string{prefix + "-source", prefix + "-destination"} }},
		{"link", func(prefix string) []string { return []string{prefix + "-source", prefix + "-destination"} }},
	} {
		for _, variant := range []struct {
			name, exe, app, verdict string
			allowed                 bool
		}{
			{"allowed", allowExe, allowName, "allow", true},
			{"denied", denyExe, denyName, "deny", false},
		} {
			prefix := filepath.Join(base, tc.op+"-"+variant.name)
			args := tc.args(prefix)
			if tc.op == "delete" || tc.op == "rename" || tc.op == "link" {
				must(os.WriteFile(args[0], []byte("m4"), 0o644))
			}
			got := m4Run(variant.exe, append([]string{tc.op}, args...)...)
			report(got == variant.allowed, fmt.Sprintf("%s %s syscall: allowed=%v", variant.name, tc.op, got))
			dest := ""
			if len(args) == 2 {
				dest = args[1]
			}
			record, err := m4WaitRecord(tc.op, variant.verdict, args[0], dest, variant.app)
			report(err == nil, fmt.Sprintf("Monitor %s %s, full paths and app: %v", variant.name, tc.op, err))
			if *debug && err == nil {
				fmt.Printf("    record %+v\n", record)
			}
			if tc.op == "delete" && !variant.allowed {
				m4AllowRetry(denyExe, args[0], denyName, record.Profile)
			}
		}
	}

	must(setMode("audit"))
	auditPath := filepath.Join(base, "audit-delete-source")
	must(os.WriteFile(auditPath, []byte("m4"), 0o644))
	report(m4Run(denyExe, "delete", auditPath), "audit would-deny syscall allowed")
	_, err = m4WaitRecord("delete", "would-deny", auditPath, "", denyName)
	report(err == nil, fmt.Sprintf("Monitor audit would-deny: %v", err))
	time.Sleep(time.Second)
	notices, err := m4Notices()
	report(err == nil, fmt.Sprintf("query notices after audit: %v", err))
	if err == nil {
		found := false
		for _, notice := range notices {
			found = found || strings.Contains(notice.Message, auditPath)
		}
		report(!found, "audit produced no deny notice")
	}

	must(setMode("enforce"))
	before, err := getDiagnostics()
	must(err)
	for i := 0; i < 10000; i++ {
		must(os.WriteFile(filepath.Join(base, fmt.Sprintf("burst-%05d", i)), nil, 0o644))
	}
	report(m4Run(allowExe, "burst", base), "10,000 deletes allowed")
	drops := uint64(0)
	for i := 0; i < 20; i++ {
		d, err := getDiagnostics()
		if err == nil {
			drops = d.Structural.DecisionDrops - before.Structural.DecisionDrops
			if drops > 0 {
				break
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	report(drops > 0, fmt.Sprintf("suppressor counted %d dropped records", drops))
	d, err := getDiagnostics()
	report(err == nil && d.Structural.State == "active", "daemon healthy after burst")
}

func m4Run(exe string, args ...string) bool {
	cmd := exec.Command(exe, append([]string{"--m4-helper"}, args...)...)
	out, err := cmd.CombinedOutput()
	if *debug || err != nil {
		fmt.Printf("    %s %v: %v %s\n", exe, args, err, strings.TrimSpace(string(out)))
	}
	return err == nil
}

func m4Records() ([]m4Record, error) {
	resp, err := http.Post("http://127.0.0.1:818/api/v1/filequery/query", "application/json", strings.NewReader(`{"pageSize":100,"orderBy":[{"field":"id","desc":true}]}`))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("filequery status %s: %.300s", resp.Status, body)
	}
	var rows struct {
		Results []m4Record `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, err
	}
	return rows.Results, nil
}

func m4WaitRecord(op, verdict, path, dest, app string) (m4Record, error) {
	var rows []m4Record
	for i := 0; i < 40; i++ {
		var err error
		rows, err = m4Records()
		if err != nil {
			return m4Record{}, err
		}
		for _, row := range rows {
			if row.Op == op && row.Path == path && row.DestPath == dest && row.Verdict == verdict && row.AppName == app {
				return row, nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return m4Record{}, fmt.Errorf("missing op=%s verdict=%s path=%s dest=%s app=%s in %d recent records", op, verdict, path, dest, app, len(rows))
}

func m4Notices() ([]m4Notice, error) {
	messageID++
	id := fmt.Sprint(messageID)
	if err := wsConn.WriteMessage(websocket.TextMessage, []byte(id+"|query|query notifications:all/")); err != nil {
		return nil, err
	}
	if err := wsConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	var notices []m4Notice
	for {
		_, raw, err := wsConn.ReadMessage()
		if err != nil {
			return nil, err
		}
		parts := strings.SplitN(string(raw), "|", 4)
		if len(parts) < 2 || parts[0] != id {
			continue
		}
		if parts[1] == "done" {
			return notices, nil
		}
		if parts[1] == "error" || parts[1] == "warning" {
			return nil, fmt.Errorf("notification query: %s", raw)
		}
		if len(parts) != 4 || !strings.HasPrefix(parts[2], "notifications:all/") {
			continue
		}
		var notice m4Notice
		if err := json.Unmarshal([]byte(strings.TrimPrefix(parts[3], "J")), &notice); err != nil {
			return nil, err
		}
		notice.Key = parts[2]
		notices = append(notices, notice)
	}
}

func m4AllowRetry(exe, path, app, scopedID string) {
	var notice m4Notice
	found := false
	for i := 0; i < 40; i++ {
		rows, err := m4Notices()
		if err != nil {
			report(false, fmt.Sprintf("query deny notice: %v", err))
			return
		}
		for _, row := range rows {
			if row.Type == 0 && strings.Contains(row.Message, path) && strings.Contains(row.Message, app) {
				notice, found = row, true
				break
			}
		}
		if found {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	report(found, "informational deny notice names app and path")
	if !found {
		return
	}
	report(!m4Run(exe, "delete", path), "repeated deny still blocks")
	rows, err := m4Notices()
	if err != nil {
		report(false, fmt.Sprintf("query repeated deny notices: %v", err))
		return
	}
	count := 0
	for _, row := range rows {
		if row.Type == 0 && strings.Contains(row.Message, path) && strings.Contains(row.Message, app) {
			count++
		}
	}
	report(count == 1, fmt.Sprintf("repeated deny deduplicated to one notice (got %d)", count))
	action := ""
	for _, available := range notice.AvailableActions {
		if available.Text == "Allow" {
			action = available.ID
			break
		}
	}
	report(action != "", "deny notice offers Allow")
	if action == "" {
		return
	}
	data, err := json.Marshal(map[string]string{"SelectedActionID": action})
	must(err)
	reply := dbRequest("update|" + notice.Key + "|J" + string(data))
	report(strings.Contains(reply, "|success"), "Allow action accepted")
	if !strings.Contains(reply, "|success") {
		return
	}
	if *debug {
		time.Sleep(250 * time.Millisecond)
		fmt.Println("    profile after Allow:", dbRequest("get|core:profiles/"+scopedID))
	}
	allowed := false
	for i := 0; i < 40; i++ {
		if m4Run(exe, "delete", path) {
			allowed = true
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	report(allowed, "retry after Allow succeeds")
	if allowed {
		_, err := m4WaitRecord("delete", "allow", path, "", app)
		report(err == nil, fmt.Sprintf("Monitor records allowed retry: %v", err))
	}
}
