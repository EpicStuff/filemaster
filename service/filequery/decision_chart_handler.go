// Ported from service/netquery/active_chart_handler.go — adapts its bounded
// recursive time series to FileQuery decision counts.
package filequery

import (
	"encoding/json"
	"net/http"

	"github.com/safing/portmaster/service/filequery/orm"
)

const (
	decisionChartBucketSeconds = 10
	decisionChartWindowSeconds = 10 * 60
)

// DecisionChartHandler serves a complete, bounded decision-count time series.
type DecisionChartHandler struct {
	Database *Database
}

func (ch *DecisionChartHandler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		resp.Header().Set("Allow", http.MethodGet)
		http.Error(resp, "invalid HTTP method", http.StatusMethodNotAllowed)
		return
	}

	var result []map[string]interface{}
	if err := ch.Database.Execute(
		req.Context(),
		decisionChartSQL,
		orm.WithResult(&result),
		orm.WithSchema(*ch.Database.Schema),
	); err != nil {
		http.Error(resp, failedQuery+err.Error(), http.StatusInternalServerError)
		return
	}

	resp.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(resp).Encode(map[string]interface{}{"results": result}); err != nil {
		http.Error(resp, "failed to encode response", http.StatusInternalServerError)
	}
}

const decisionChartSQL = `
WITH RECURSIVE bounds(end_timestamp) AS (
	SELECT (CAST(strftime('%s') AS INTEGER) / 10) * 10
), epoch(timestamp) AS (
	SELECT end_timestamp - 590 FROM bounds
	UNION ALL
	SELECT timestamp + 10 FROM epoch, bounds WHERE timestamp < end_timestamp
)
SELECT
	epoch.timestamp AS timestamp,
	COALESCE(SUM(file_events.op = 'open' AND file_events.verdict = 'allow'), 0) AS open_allowed,
	COALESCE(SUM(file_events.op = 'open' AND file_events.verdict = 'deny'), 0) AS open_blocked,
	COALESCE(SUM(file_events.op = 'exec' AND file_events.verdict = 'allow'), 0) AS execute_allowed,
	COALESCE(SUM(file_events.op = 'exec' AND file_events.verdict = 'deny'), 0) AS execute_blocked
FROM epoch
LEFT JOIN file_events
	ON CAST(strftime('%s', file_events.at) AS INTEGER) >= epoch.timestamp
	AND CAST(strftime('%s', file_events.at) AS INTEGER) < epoch.timestamp + 10
GROUP BY epoch.timestamp
ORDER BY epoch.timestamp;`
