// Filemaster-specific: provides the per-mount activity aggregate needed to
// order current protected mounts without scanning a bounded event page.
package filequery

import (
	"encoding/json"
	"net/http"

	"github.com/safing/portmaster/service/filequery/orm"
)

// MountActivityHandler serves per-mount decision counts and latest activity.
type MountActivityHandler struct {
	Database *Database
}

func (mh *MountActivityHandler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		resp.Header().Set("Allow", http.MethodGet)
		http.Error(resp, "invalid HTTP method", http.StatusMethodNotAllowed)
		return
	}

	var result []map[string]interface{}
	if err := mh.Database.Execute(
		req.Context(),
		mountActivitySQL,
		orm.WithResult(&result),
		orm.WithSchema(*mh.Database.Schema),
	); err != nil {
		http.Error(resp, failedQuery+err.Error(), http.StatusInternalServerError)
		return
	}

	resp.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(resp).Encode(map[string]interface{}{"results": result}); err != nil {
		http.Error(resp, "failed to encode response", http.StatusInternalServerError)
	}
}

const mountActivitySQL = `
SELECT
	mount_id,
	mount_path,
	MAX(at) AS last_activity_at,
	COALESCE(SUM(op = 'open' AND verdict = 'allow'), 0) AS open_allowed,
	COALESCE(SUM(op = 'open' AND verdict = 'deny'), 0) AS open_blocked,
	COALESCE(SUM(op = 'exec' AND verdict = 'allow'), 0) AS execute_allowed,
	COALESCE(SUM(op = 'exec' AND verdict = 'deny'), 0) AS execute_blocked
FROM file_events
WHERE mount_id != 0 AND mount_path != ''
GROUP BY mount_id, mount_path
ORDER BY last_activity_at DESC, mount_id ASC;`
