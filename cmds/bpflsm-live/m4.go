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
	scopedExe := filepath.Join(*outside, "m4-scoped-helper")
	for _, target := range []string{allowExe, denyExe, scopedExe} {
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
	scopedName := "M4 scoped app"
	scopedFP := []map[string]string{{"Type": "path", "Operation": "equals", "Value": scopedExe}}
	putProfile(scopedName, scopedFP, map[string]any{
		"filter":     map[string]any{"defaultAction": "block"},
		"fileaccess": map[string]any{"writeRules": []string{"+ " + *scope + "/**"}},
	})
	must(setMode("enforce"))
	report(m4Run(allowExe, "noop"), "allow helper learned")
	report(m4Run(denyExe, "noop"), "deny helper learned")
	report(m4Run(scopedExe, "noop"), "scoped helper learned")

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

	// Profile-default (NOMATCH) denials on objects outside every scope. The
	// unscoped folder shares the scope's mount, so a rename reaches the hook.
	unscoped := filepath.Join(filepath.Dir(*scope), "m4-unscoped")
	must(os.RemoveAll(unscoped))
	must(os.MkdirAll(unscoped, 0o755))
	outsideDelete := filepath.Join(unscoped, "default-delete")
	must(os.WriteFile(outsideDelete, []byte("m4"), 0o644))
	report(m4Run(scopedExe, "delete", outsideDelete), "delete outside every scope allowed (not covered)")
	renameSource := filepath.Join(base, "default-rename-source")
	must(os.WriteFile(renameSource, []byte("m4"), 0o644))
	renameDest := filepath.Join(unscoped, "default-rename-destination")
	report(!m4Run(scopedExe, "rename", renameSource, renameDest), "rename to outside every scope denied by the profile default")
	row, err := m4WaitAny("rename", "deny", renameSource, scopedName)
	report(err == nil, fmt.Sprintf("Monitor records the default-denied rename (dest %q): %v", row.DestPath, err))
	time.Sleep(500 * time.Millisecond)
	rows, err := m4Records()
	must(err)
	recorded := false
	for _, row := range rows {
		recorded = recorded || row.Path == outsideDelete
	}
	report(!recorded, "uncovered delete outside every scope has no Monitor record")
	notices, err := m4Notices()
	must(err)
	noticed := false
	for _, notice := range notices {
		noticed = noticed || notice.Type == 0 && strings.Contains(notice.Message, renameSource)
	}
	report(noticed, "default-denied rename raises a deny notice")

	must(setMode("audit"))
	auditPath := filepath.Join(base, "audit-delete-source")
	must(os.WriteFile(auditPath, []byte("m4"), 0o644))
	report(m4Run(denyExe, "delete", auditPath), "audit would-deny syscall allowed")
	_, err = m4WaitRecord("delete", "would-deny", auditPath, "", denyName)
	report(err == nil, fmt.Sprintf("Monitor audit would-deny: %v", err))
	time.Sleep(time.Second)
	notices, err = m4Notices()
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

	// The same app's deletes spread over one process each, as `find -exec rm`
	// or `xargs -n1 rm` would: the budget is the app's, so most are dropped.
	const spread = 10000
	for i := 0; i < spread; i++ {
		must(os.WriteFile(filepath.Join(base, fmt.Sprintf("spread-%05d", i)), nil, 0o644))
	}
	mid, err := getDiagnostics()
	must(err)
	started := time.Now()
	failed := m4Spread(allowExe, base, spread)
	elapsed := time.Since(started)
	report(failed == 0, fmt.Sprintf("%d deletes by %d processes allowed in %s (%d failed)", spread, spread, elapsed.Round(time.Millisecond), failed))
	// At most one window's budget per started second, plus the window open at the start.
	budget := uint64(64 * (int(elapsed/time.Second) + 2))
	time.Sleep(500 * time.Millisecond)
	d, err = getDiagnostics()
	must(err)
	spreadDrops := d.Structural.DecisionDrops - mid.Structural.DecisionDrops
	report(spreadDrops+budget >= spread, fmt.Sprintf("multi-process burst: %d of %d records dropped (at most %d emitted)", spreadDrops, spread, budget))
	// A window's drop count rides on the key's first record of the next window.
	time.Sleep(1100 * time.Millisecond)
	flush := filepath.Join(base, "spread-flush")
	must(os.WriteFile(flush, nil, 0o644))
	report(m4Run(allowExe, "delete", flush), "delete after the burst windows allowed")
	_, err = m4WaitRecord("delete", "allow", flush, "", allowName)
	report(err == nil, fmt.Sprintf("Monitor records the delete after the bursts: %v", err))
	d, err = getDiagnostics()
	must(err)
	allDrops := d.Structural.DecisionDrops - before.Structural.DecisionDrops
	suppressed := d.Structural.DecisionSuppressed - before.Structural.DecisionSuppressed
	report(suppressed > 0 && suppressed <= allDrops, fmt.Sprintf("records reported %d suppressed of %d dropped", suppressed, allDrops))
	report(d.Structural.State == "active", "daemon healthy after multi-process burst")
}

// m4Spread deletes `spread-%05d` files in dir with one helper process each,
// four at a time, and returns how many failed.
func m4Spread(exe, dir string, count int) int {
	jobs := make(chan int)
	failures := make(chan int, 4)
	for w := 0; w < 4; w++ {
		go func() {
			failed := 0
			for i := range jobs {
				path := filepath.Join(dir, fmt.Sprintf("spread-%05d", i))
				if err := exec.Command(exe, "--m4-helper", "delete", path).Run(); err != nil {
					failed++
				}
			}
			failures <- failed
		}()
	}
	for i := 0; i < count; i++ {
		jobs <- i
	}
	close(jobs)
	failed := 0
	for w := 0; w < 4; w++ {
		failed += <-failures
	}
	return failed
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

// m4WaitAny waits for a record of op, verdict, source path and app, whatever
// its destination.
func m4WaitAny(op, verdict, path, app string) (m4Record, error) {
	for i := 0; i < 40; i++ {
		rows, err := m4Records()
		if err != nil {
			return m4Record{}, err
		}
		for _, row := range rows {
			if row.Op == op && row.Path == path && row.Verdict == verdict && row.AppName == app {
				return row, nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return m4Record{}, fmt.Errorf("missing op=%s verdict=%s path=%s app=%s", op, verdict, path, app)
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
