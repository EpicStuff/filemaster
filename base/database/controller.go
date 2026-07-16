package database

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/safing/portmaster/base/database/iterator"
	"github.com/safing/portmaster/base/database/query"
	"github.com/safing/portmaster/base/database/record"
	"github.com/safing/portmaster/base/database/storage"
)

const recordWriteLockStripes = 257

// A Controller takes care of all the extra database logic.
type Controller struct {
	database     *Database
	storage      storage.Interface
	shadowDelete bool

	// recordWriteLocks cover validation hooks and the storage commit together.
	// Fixed stripes keep this transaction boundary bounded even for databases
	// with an unbounded number of historical keys.
	recordWriteLocks [recordWriteLockStripes]sync.Mutex

	hooksLock sync.RWMutex
	hooks     []*RegisteredHook

	subscriptionLock sync.RWMutex
	subscriptions    []*Subscription
}

// newController creates a new controller for a storage.
func newController(database *Database, storageInt storage.Interface, shadowDelete bool) *Controller {
	return &Controller{
		database:     database,
		storage:      storageInt,
		shadowDelete: shadowDelete,
	}
}

// ReadOnly returns whether the storage is read only.
func (c *Controller) ReadOnly() bool {
	return c.storage.ReadOnly()
}

// Injected returns whether the storage is injected.
func (c *Controller) Injected() bool {
	return c.storage.Injected()
}

// Get returns the record with the given key.
func (c *Controller) Get(key string) (record.Record, error) {
	if shuttingDown.IsSet() {
		return nil, ErrShuttingDown
	}

	if err := c.runPreGetHooks(key); err != nil {
		return nil, err
	}

	r, err := c.storage.Get(key)
	if err != nil {
		// replace not found error
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	r.Lock()
	defer r.Unlock()

	r, err = c.runPostGetHooks(r)
	if err != nil {
		return nil, err
	}

	if !r.Meta().CheckValidity() {
		return nil, ErrNotFound
	}

	return r, nil
}

// GetMeta returns the metadata of the record with the given key.
func (c *Controller) GetMeta(key string) (*record.Meta, error) {
	if shuttingDown.IsSet() {
		return nil, ErrShuttingDown
	}

	var m *record.Meta
	var err error
	if metaDB, ok := c.storage.(storage.MetaHandler); ok {
		m, err = metaDB.GetMeta(key)
		if err != nil {
			// replace not found error
			if errors.Is(err, storage.ErrNotFound) {
				return nil, ErrNotFound
			}
			return nil, err
		}
	} else {
		r, err := c.storage.Get(key)
		if err != nil {
			// replace not found error
			if errors.Is(err, storage.ErrNotFound) {
				return nil, ErrNotFound
			}
			return nil, err
		}
		m = r.Meta()
	}

	if !m.CheckValidity() {
		return nil, ErrNotFound
	}

	return m, nil
}

// Put saves a record in the database, executes any registered
// pre-put hooks and finally send an update to all subscribers.
// The record must be locked and secured from concurrent access
// when calling Put().
func (c *Controller) Put(r record.Record) (err error) {
	if shuttingDown.IsSet() {
		return ErrShuttingDown
	}

	if c.ReadOnly() {
		return ErrReadOnly
	}
	submitted := r
	lockedKey := r.Key()
	mu := c.recordWriteLock(r.DatabaseKey())
	mu.Lock()
	defer mu.Unlock()

	carrier, releaseCarrier, err := c.runPrePutHooks(r)
	if err != nil {
		return err
	}
	defer releaseCarrier()
	if carrier.Key() != lockedKey {
		return fmt.Errorf("database pre put hook changed locked record key from %q to %q", lockedKey, carrier.Key())
	}
	transactional, _ := carrier.(interface{ CommitRecordTransaction() })
	notificationRecord := carrier

	if !c.shadowDelete && carrier.Meta().IsDeleted() {
		// Immediate delete.
		err = c.storage.Delete(carrier.DatabaseKey())
	} else {
		// Put or shadow delete.
		r, err = c.storage.Put(carrier)
	}

	if err != nil {
		return err
	}

	if r == nil {
		return errors.New("storage returned nil record after successful put operation")
	}
	if transactional != nil {
		transactional.CommitRecordTransaction()
		if committed, ok := carrier.(interface{ TakeCommittedRecord() record.Record }); ok {
			notificationRecord = committed.TakeCommittedRecord()
		}
	} else {
		notificationRecord = r
	}

	if !sameRecord(notificationRecord, carrier) && !sameRecord(notificationRecord, submitted) {
		notificationRecord.Lock()
		defer notificationRecord.Unlock()
	}
	c.notifySubscribers(notificationRecord)

	return nil
}

func (c *Controller) recordWriteLock(key string) *sync.Mutex {
	// FNV-1a provides a stable distribution without retaining a mutex per key.
	hash := uint64(14695981039346656037)
	for i := 0; i < len(key); i++ {
		hash ^= uint64(key[i])
		hash *= 1099511628211
	}
	return &c.recordWriteLocks[hash%recordWriteLockStripes]
}

// PutMany stores many records through the same hooks, record transaction, and
// subscriber notification path as Put. After its first failure it drains the
// remaining input until the caller closes the batch and reports that error.
func (c *Controller) PutMany() (chan<- record.Record, <-chan error) {
	if shuttingDown.IsSet() {
		errs := make(chan error, 1)
		errs <- ErrShuttingDown
		return make(chan record.Record), errs
	}

	if c.ReadOnly() {
		errs := make(chan error, 1)
		errs <- ErrReadOnly
		return make(chan record.Record), errs
	}

	// Do not delegate directly to a storage batcher: it would bypass both
	// Controller.Put hooks and its per-record transaction lock. A single batch
	// worker preserves the public streaming API while every record follows the
	// same validation and commit path as a normal Put.
	batch := make(chan record.Record)
	errs := make(chan error, 1)
	go func() {
		defer close(errs)
		var firstErr error
		for r := range batch {
			if firstErr != nil {
				// Continue draining submissions so a producer can always finish the
				// batch after an earlier failure.
				continue
			}
			r.Lock()
			err := c.Put(r)
			r.Unlock()
			if err != nil {
				firstErr = err
				errs <- err
			}
		}
	}()
	return batch, errs
}

// Query executes the given query on the database.
func (c *Controller) Query(q *query.Query, local, internal bool) (*iterator.Iterator, error) {
	if shuttingDown.IsSet() {
		return nil, ErrShuttingDown
	}

	it, err := c.storage.Query(q, local, internal)
	if err != nil {
		return nil, err
	}

	return it, nil
}

// PushUpdate pushes a record update to subscribers.
// The caller must hold the record's lock when calling
// PushUpdate.
func (c *Controller) PushUpdate(r record.Record) {
	if c != nil {
		if shuttingDown.IsSet() {
			return
		}

		c.notifySubscribers(r)
	}
}

func (c *Controller) addSubscription(sub *Subscription) {
	if shuttingDown.IsSet() {
		return
	}

	c.subscriptionLock.Lock()
	defer c.subscriptionLock.Unlock()

	c.subscriptions = append(c.subscriptions, sub)
}

// Maintain runs the Maintain method on the storage.
func (c *Controller) Maintain(ctx context.Context) error {
	if shuttingDown.IsSet() {
		return ErrShuttingDown
	}

	if maintainer, ok := c.storage.(storage.Maintainer); ok {
		return maintainer.Maintain(ctx)
	}
	return nil
}

// MaintainThorough runs the MaintainThorough method on the
// storage.
func (c *Controller) MaintainThorough(ctx context.Context) error {
	if shuttingDown.IsSet() {
		return ErrShuttingDown
	}

	if maintainer, ok := c.storage.(storage.Maintainer); ok {
		return maintainer.MaintainThorough(ctx)
	}
	return nil
}

// MaintainRecordStates runs the record state lifecycle
// maintenance on the storage.
func (c *Controller) MaintainRecordStates(ctx context.Context, purgeDeletedBefore time.Time) error {
	if shuttingDown.IsSet() {
		return ErrShuttingDown
	}

	return c.storage.MaintainRecordStates(ctx, purgeDeletedBefore, c.shadowDelete)
}

// Purge deletes all records that match the given query.
// It returns the number of successful deletes and an error.
func (c *Controller) Purge(ctx context.Context, q *query.Query, local, internal bool) (int, error) {
	if shuttingDown.IsSet() {
		return 0, ErrShuttingDown
	}

	if purger, ok := c.storage.(storage.Purger); ok {
		return purger.Purge(ctx, q, local, internal, c.shadowDelete)
	}

	return 0, ErrNotImplemented
}

// PurgeOlderThan deletes all records last updated before the given time.
// It returns the number of successful deletes and an error.
func (c *Controller) PurgeOlderThan(ctx context.Context, prefix string, purgeBefore time.Time, local, internal bool) (int, error) {
	if shuttingDown.IsSet() {
		return 0, ErrShuttingDown
	}

	if purger, ok := c.storage.(storage.PurgeOlderThan); ok {
		return purger.PurgeOlderThan(ctx, prefix, purgeBefore, local, internal, c.shadowDelete)
	}

	return 0, ErrNotImplemented
}

// Shutdown shuts down the storage.
func (c *Controller) Shutdown() error {
	return c.storage.Shutdown()
}

// notifySubscribers notifies all subscribers that are interested
// in r. r must be locked when calling notifySubscribers.
// Any subscriber that is not blocking on it's feed channel will
// be skipped.
// notifySubscribers requires r to remain locked for the full matching and
// delivery iteration so subscribers cannot mutate it between feed checks.
func (c *Controller) notifySubscribers(r record.Record) {
	c.subscriptionLock.RLock()
	defer c.subscriptionLock.RUnlock()

	for _, sub := range c.subscriptions {
		if r.Meta().CheckPermission(sub.local, sub.internal) && sub.q.Matches(r) {
			select {
			case sub.Feed <- r:
			default:
			}
		}
	}
}

func sameRecord(a, b record.Record) bool {
	if a == nil || b == nil {
		return a == b
	}
	typeA := reflect.TypeOf(a)
	if typeA != reflect.TypeOf(b) || !typeA.Comparable() {
		return false
	}
	return a == b
}

func (c *Controller) runPreGetHooks(key string) error {
	c.hooksLock.RLock()
	defer c.hooksLock.RUnlock()

	for _, hook := range c.hooks {
		if !hook.h.UsesPreGet() {
			continue
		}

		if !hook.q.MatchesKey(key) {
			continue
		}

		if err := hook.h.PreGet(key); err != nil {
			return err
		}
	}

	return nil
}

func (c *Controller) runPostGetHooks(r record.Record) (record.Record, error) {
	c.hooksLock.RLock()
	defer c.hooksLock.RUnlock()

	var err error
	for _, hook := range c.hooks {
		if !hook.h.UsesPostGet() {
			continue
		}

		if !hook.q.Matches(r) {
			continue
		}

		r, err = hook.h.PostGet(r)
		if err != nil {
			return nil, err
		}
	}

	return r, nil
}

// runPrePutHooks keeps the caller-owned initial record locked. A hook that
// replaces it must return an unlocked replacement; the controller locks that
// replacement before invoking another hook and releases it through cleanup.
func (c *Controller) runPrePutHooks(r record.Record) (record.Record, func(), error) {
	c.hooksLock.RLock()
	defer c.hooksLock.RUnlock()

	original := r
	current := r
	var owned record.Record
	cleanup := func() {
		if owned != nil {
			owned.Unlock()
		}
	}
	for _, hook := range c.hooks {
		if !hook.h.UsesPrePut() {
			continue
		}

		if !hook.q.Matches(current) {
			continue
		}

		next, err := hook.h.PrePut(current)
		if err != nil {
			cleanup()
			return nil, nil, err
		}
		if next == nil {
			cleanup()
			return nil, nil, errors.New("database pre put hook returned nil record")
		}
		if sameRecord(next, current) {
			continue
		}
		if sameRecord(next, original) {
			if owned != nil {
				owned.Unlock()
				owned = nil
			}
			current = original
			continue
		}
		next.Lock()
		if owned != nil {
			owned.Unlock()
		}
		owned = next
		current = next
	}

	return current, cleanup, nil
}
