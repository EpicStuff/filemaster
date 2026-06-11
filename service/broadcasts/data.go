package broadcasts

import (
	"strconv"
	"time"

	"github.com/safing/portmaster/base/config"
	"github.com/safing/portmaster/service/core"
)

var portmasterStarted = time.Now()

func collectData() interface{} {
	data := make(map[string]interface{})

	// Get data about versions.
	versions := core.GetSimpleVersions()
	data["Updates"] = versions
	data["Version"] = versions.Build.Version
	numericVersion, err := MakeNumericVersion(versions.Build.Version)
	if err != nil {
		data["NumericVersion"] = &DataError{
			Error: err,
		}
	} else {
		data["NumericVersion"] = numericVersion
	}

	// Get data about install.
	installInfo, err := GetInstallInfo()
	if err != nil {
		data["Install"] = &DataError{
			Error: err,
		}
	} else {
		data["Install"] = installInfo
	}

	// Get global configuration.
	data["Config"] = config.GetActiveConfigValues()

	// Time running.
	data["UptimeHours"] = int(time.Since(portmasterStarted).Hours())

	// Get current time and date.
	now := time.Now()
	data["Current"] = &Current{
		UnixTime: now.Unix(),
		UTC:      makeDateTimeInfo(now.UTC()),
		Local:    makeDateTimeInfo(now),
	}

	return data
}

// DataError represents an error getting some matching data.
type DataError struct {
	Error error
}

// Current holds current date and time data.
type Current struct {
	UnixTime int64
	UTC      *DateTime
	Local    *DateTime
}

// DateTime holds date and time data in different formats.
type DateTime struct {
	NumericDateTime int64
	NumericDate     int64
	NumericTime     int64
}

func makeDateTimeInfo(t time.Time) *DateTime {
	info := &DateTime{}
	info.NumericDateTime, _ = strconv.ParseInt(t.Format("20060102150405"), 10, 64)
	info.NumericDate, _ = strconv.ParseInt(t.Format("20060102"), 10, 64)
	info.NumericTime, _ = strconv.ParseInt(t.Format("150405"), 10, 64)

	return info
}
