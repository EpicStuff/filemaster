package fileaccess

// Registers the process tag handlers (interpreter scripts, AppImage, Flatpak,
// Snap). Upstream Portmaster imports them from service/network/connection.go,
// which this fork deleted with the network stack; without this import no
// process is ever tagged, so script and app-bundle profiles never match.
import _ "github.com/safing/portmaster/service/process/tags"
