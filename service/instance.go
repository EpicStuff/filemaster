package service

import (
	"context"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/safing/portmaster/base/api"
	"github.com/safing/portmaster/base/config"
	"github.com/safing/portmaster/base/database/dbmodule"
	"github.com/safing/portmaster/base/metrics"
	"github.com/safing/portmaster/base/notifications"
	"github.com/safing/portmaster/base/rng"
	"github.com/safing/portmaster/base/runtime"
	"github.com/safing/portmaster/base/utils"
	"github.com/safing/portmaster/service/broadcasts"
	"github.com/safing/portmaster/service/core"
	"github.com/safing/portmaster/service/core/base"
	"github.com/safing/portmaster/service/fileaccess"
	"github.com/safing/portmaster/service/integration"
	"github.com/safing/portmaster/service/mgr"
	"github.com/safing/portmaster/service/process"
	"github.com/safing/portmaster/service/profile"
	"github.com/safing/portmaster/service/status"
	"github.com/safing/portmaster/service/sync"
	"github.com/safing/portmaster/service/ui"
	"github.com/safing/portmaster/service/updates"
)

// Instance is an instance of a filemaster service.
type Instance struct {
	ctx       context.Context
	cancelCtx context.CancelFunc

	shutdownCtx       context.Context
	cancelShutdownCtx context.CancelFunc

	serviceGroup *mgr.Group

	binDir  string
	dataDir string

	exitCode atomic.Int32

	database      *dbmodule.DBModule
	config        *config.Config
	api           *api.API
	metrics       *metrics.Metrics
	runtime       *runtime.Runtime
	notifications *notifications.Notifications
	rng           *rng.Rng
	base          *base.Base

	core          *core.Core
	binaryUpdates *updates.Updater
	intelUpdates  *updates.Updater
	integration   *integration.OSIntegration
	ui            *ui.UI
	profile       *profile.ProfileModule
	process       *process.ProcessModule
	status        *status.Status
	broadcasts    *broadcasts.Broadcasts
	sync          *sync.Sync
	fileAccess    *fileaccess.FileAccess

	CommandLineOperation func() error
	ShouldRestart        bool
}

// New returns a new filemaster service instance.
func New(svcCfg *ServiceConfig) (*Instance, error) {
	// Initialize config.
	err := svcCfg.Init()
	if err != nil {
		return nil, fmt.Errorf("internal service config error: %w", err)
	}

	// Make sure data dir exists, so that child directories don't dictate the permissions.
	err = utils.EnsureDirectory(svcCfg.DataDir, utils.PublicReadExecPermission)
	if err != nil {
		return nil, fmt.Errorf("data directory %s is not accessible: %w", svcCfg.DataDir, err)
	}

	// Create instance to pass it to modules.
	instance := &Instance{
		binDir:  svcCfg.BinDir,
		dataDir: svcCfg.DataDir,
	}
	instance.ctx, instance.cancelCtx = context.WithCancel(context.Background())
	instance.shutdownCtx, instance.cancelShutdownCtx = context.WithCancel(context.Background())

	// Base modules
	instance.base, err = base.New(instance)
	if err != nil {
		return instance, fmt.Errorf("create base module: %w", err)
	}
	instance.database, err = dbmodule.New(instance)
	if err != nil {
		return instance, fmt.Errorf("create database module: %w", err)
	}
	instance.config, err = config.New(instance)
	if err != nil {
		return instance, fmt.Errorf("create config module: %w", err)
	}
	instance.api, err = api.New(instance)
	if err != nil {
		return instance, fmt.Errorf("create api module: %w", err)
	}
	instance.metrics, err = metrics.New(instance)
	if err != nil {
		return instance, fmt.Errorf("create metrics module: %w", err)
	}
	instance.runtime, err = runtime.New(instance)
	if err != nil {
		return instance, fmt.Errorf("create runtime module: %w", err)
	}
	instance.notifications, err = notifications.New(instance)
	if err != nil {
		return instance, fmt.Errorf("create notifications module: %w", err)
	}
	instance.rng, err = rng.New(instance)
	if err != nil {
		return instance, fmt.Errorf("create rng module: %w", err)
	}

	// Service modules
	binaryUpdateConfig, intelUpdateConfig, err := MakeUpdateConfigs(svcCfg)
	if err != nil {
		return instance, fmt.Errorf("create updates config: %w", err)
	}
	instance.binaryUpdates, err = updates.New(instance, "Binary Updater", *binaryUpdateConfig)
	if err != nil {
		return instance, fmt.Errorf("create updates module: %w", err)
	}
	instance.intelUpdates, err = updates.New(instance, "Intel Updater", *intelUpdateConfig)
	if err != nil {
		return instance, fmt.Errorf("create updates module: %w", err)
	}
	instance.core, err = core.New(instance)
	if err != nil {
		return instance, fmt.Errorf("create core module: %w", err)
	}
	instance.integration, err = integration.New(instance)
	if err != nil {
		return instance, fmt.Errorf("create integration module: %w", err)
	}
	instance.ui, err = ui.New(instance)
	if err != nil {
		return instance, fmt.Errorf("create ui module: %w", err)
	}
	instance.profile, err = profile.NewModule(instance)
	if err != nil {
		return instance, fmt.Errorf("create profile module: %w", err)
	}
	instance.status, err = status.New(instance)
	if err != nil {
		return instance, fmt.Errorf("create status module: %w", err)
	}
	instance.broadcasts, err = broadcasts.New(instance)
	if err != nil {
		return instance, fmt.Errorf("create broadcasts module: %w", err)
	}
	instance.process, err = process.New(instance)
	if err != nil {
		return instance, fmt.Errorf("create process module: %w", err)
	}
	instance.sync, err = sync.New(instance)
	if err != nil {
		return instance, fmt.Errorf("create sync module: %w", err)
	}
	instance.fileAccess, err = fileaccess.New(instance)
	if err != nil {
		return instance, fmt.Errorf("create fileaccess module: %w", err)
	}
	// Wire the prompt-driven handler: rules first, then notifications
	// prompt on miss, with allow/deny-always responses persisted as new
	// rules. Default-deny on timeout (30s). Rules persist to a JSON
	// file under the data dir so they survive restarts.
	promptHandler := fileaccess.NewPromptHandler(
		&fileaccess.NotificationsPrompter{},
		nil,
		30*time.Second,
	)
	rulesPath := filepath.Join(svcCfg.DataDir, "fileaccess-rules.json")
	if err := promptHandler.SetPersistPath(rulesPath); err != nil {
		return instance, fmt.Errorf("load file-access rules from %s: %w", rulesPath, err)
	}
	instance.fileAccess.SetHandler(promptHandler)

	// Add all modules to instance group.
	instance.serviceGroup = mgr.NewGroup(
		instance.base,
		instance.rng,
		instance.database,
		instance.config,
		instance.api,
		instance.metrics,
		instance.runtime,
		instance.notifications,

		instance.core,
		instance.binaryUpdates,
		instance.intelUpdates,
		instance.integration,

		instance.process,
		instance.profile,
		instance.fileAccess,

		instance.status,
		instance.broadcasts,
		instance.sync,
		instance.ui,
	)

	return instance, nil
}

// SleepyModule is an interface for modules that can enter some sort of sleep mode.
type SleepyModule interface {
	SetSleep(enabled bool)
}

// SetSleep sets sleep mode on all modules that satisfy the SleepyModule interface.
func (i *Instance) SetSleep(enabled bool) {
	for _, module := range i.serviceGroup.Modules() {
		if sm, ok := module.(SleepyModule); ok {
			sm.SetSleep(enabled)
		}
	}
}

// BinDir returns the directory for binaries.
// This directory may be read-only.
func (i *Instance) BinDir() string {
	return i.binDir
}

// DataDir returns the directory for variable data.
// This directory is expected to be read/writeable.
func (i *Instance) DataDir() string {
	return i.dataDir
}

// Database returns the database module.
func (i *Instance) Database() *dbmodule.DBModule {
	return i.database
}

// Config returns the config module.
func (i *Instance) Config() *config.Config {
	return i.config
}

// API returns the api module.
func (i *Instance) API() *api.API {
	return i.api
}

// Metrics returns the metrics module.
func (i *Instance) Metrics() *metrics.Metrics {
	return i.metrics
}

// Runtime returns the runtime module.
func (i *Instance) Runtime() *runtime.Runtime {
	return i.runtime
}

// Notifications returns the notifications module.
func (i *Instance) Notifications() *notifications.Notifications {
	return i.notifications
}

// Rng returns the rng module.
func (i *Instance) Rng() *rng.Rng {
	return i.rng
}

// Base returns the base module.
func (i *Instance) Base() *base.Base {
	return i.base
}

// BinaryUpdates returns the updates module.
func (i *Instance) BinaryUpdates() *updates.Updater {
	return i.binaryUpdates
}

// GetBinaryUpdateFile returns the file path of a binary update file.
func (i *Instance) GetBinaryUpdateFile(name string) (path string, err error) {
	file, err := i.binaryUpdates.GetFile(name)
	if err != nil {
		return "", err
	}
	return file.Path(), nil
}

// IntelUpdates returns the updates module.
func (i *Instance) IntelUpdates() *updates.Updater {
	return i.intelUpdates
}

// OSIntegration returns the integration module.
func (i *Instance) OSIntegration() *integration.OSIntegration {
	return i.integration
}

// UI returns the ui module.
func (i *Instance) UI() *ui.UI {
	return i.ui
}

// Profile returns the profile module.
func (i *Instance) Profile() *profile.ProfileModule {
	return i.profile
}

// Status returns the status module.
func (i *Instance) Status() *status.Status {
	return i.status
}

// Broadcasts returns the broadcast module.
func (i *Instance) Broadcasts() *broadcasts.Broadcasts {
	return i.broadcasts
}

// Process returns the process module.
func (i *Instance) Process() *process.ProcessModule {
	return i.process
}

// Sync returns the sync module.
func (i *Instance) Sync() *sync.Sync {
	return i.sync
}

// Core returns the core module.
func (i *Instance) Core() *core.Core {
	return i.core
}

// Special functions

// SetCmdLineOperation sets a command line operation to be executed instead of starting the system. This is useful when functions need all modules to be prepared for a special operation.
func (i *Instance) SetCmdLineOperation(f func() error) {
	i.CommandLineOperation = f
}

// GetStates returns the current states of all group modules.
func (i *Instance) GetStates() []mgr.StateUpdate {
	return i.serviceGroup.GetStates()
}

// AddStatesCallback adds the given callback function to all group modules that
// expose a state manager at States().
func (i *Instance) AddStatesCallback(callbackName string, callback mgr.EventCallbackFunc[mgr.StateUpdate]) {
	i.serviceGroup.AddStatesCallback(callbackName, callback)
}

// Ready returns whether all modules in the main service module group have been started and are still running.
func (i *Instance) Ready() bool {
	return i.serviceGroup.Ready()
}

// Start starts the instance modules.
func (i *Instance) Start() error {
	return i.serviceGroup.Start()
}

// Stop stops the instance modules.
func (i *Instance) Stop() error {
	return i.serviceGroup.Stop()
}

// RestartExitCode will instruct portmaster-start to restart the process immediately, potentially with a new version.
const RestartExitCode = 23

// Restart asynchronously restarts the instance.
// This only works if the underlying system/process supports this.
func (i *Instance) Restart() {
	// Send a restart event, give it 10ms extra to propagate.
	i.core.EventRestart.Submit(struct{}{})
	time.Sleep(10 * time.Millisecond)

	// Set the restart flag and shutdown.
	i.ShouldRestart = true
	i.shutdown(RestartExitCode)
}

// Shutdown asynchronously stops the instance.
func (i *Instance) Shutdown() {
	// Send a shutdown event, give it 10ms extra to propagate.
	i.core.EventShutdown.Submit(struct{}{})
	time.Sleep(10 * time.Millisecond)

	i.shutdown(0)
}

func (i *Instance) shutdown(exitCode int) {
	// Only shutdown once.
	if i.IsShuttingDown() {
		return
	}

	// Cancel main  context.
	i.cancelCtx()

	// Set given exit code.
	i.exitCode.Store(int32(exitCode))

	// Start shutdown asynchronously in a separate manager.
	m := mgr.New("instance")
	m.Go("shutdown", func(w *mgr.WorkerCtx) error {
		// Stop all modules.
		if err := i.Stop(); err != nil {
			w.Error("failed to shutdown", "err", err)
		}

		// Cancel shutdown process context.
		i.cancelShutdownCtx()
		return nil
	})
}

// Ctx returns the instance context.
// It is canceled when shutdown is started.
func (i *Instance) Ctx() context.Context {
	return i.ctx
}

// IsShuttingDown returns whether the instance is shutting down.
func (i *Instance) IsShuttingDown() bool {
	return i.ctx.Err() != nil
}

// ShuttingDown returns a channel that is triggered when the instance starts shutting down.
func (i *Instance) ShuttingDown() <-chan struct{} {
	return i.ctx.Done()
}

// ShutdownCtx returns the instance shutdown context.
// It is canceled when shutdown is complete.
func (i *Instance) ShutdownCtx() context.Context {
	return i.shutdownCtx
}

// IsShutDown returns whether the instance has stopped.
func (i *Instance) IsShutDown() bool {
	return i.shutdownCtx.Err() != nil
}

// ShutDownComplete returns a channel that is triggered when the instance has shut down.
func (i *Instance) ShutdownComplete() <-chan struct{} {
	return i.shutdownCtx.Done()
}

// ExitCode returns the set exit code of the instance.
func (i *Instance) ExitCode() int {
	return int(i.exitCode.Load())
}

// ShouldRestartIsSet returns whether the service/instance should be restarted.
func (i *Instance) ShouldRestartIsSet() bool {
	return i.ShouldRestart
}

// CommandLineOperationIsSet returns whether the command line option is set.
func (i *Instance) CommandLineOperationIsSet() bool {
	return i.CommandLineOperation != nil
}

// CommandLineOperationExecute executes the set command line option.
func (i *Instance) CommandLineOperationExecute() error {
	return i.CommandLineOperation()
}

// AddModule adds a module to the service group.
func (i *Instance) AddModule(m mgr.Module) {
	i.serviceGroup.Add(m)
}
