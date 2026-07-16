package database

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	q "github.com/safing/portmaster/base/database/query"
	"github.com/safing/portmaster/base/database/record"
	"github.com/safing/portmaster/base/database/storage"
)

type blockingStorage struct {
	storage.InjectBase
	entered chan string
	release chan struct{}
}

func (s *blockingStorage) ReadOnly() bool { return false }

func (s *blockingStorage) Put(r record.Record) (record.Record, error) {
	s.entered <- r.DatabaseKey()
	<-s.release
	return r, nil
}

type rejectingPutHook struct {
	HookBase
	key          string
	err          error
	observedLock bool
}

type revisionRecord struct {
	record.Base
	sync.Mutex
	Revision                 uint64
	target                   *revisionRecord
	publishedUnderRecordLock bool
}

func (r *revisionRecord) CommitRecordTransaction() {
	if r.target != nil {
		if r.target.TryLock() {
			r.target.Unlock()
		} else {
			r.target.publishedUnderRecordLock = true
		}
		r.target.Revision = r.Revision
	}
}

type revisionHook struct{ HookBase }

func (h *revisionHook) UsesPrePut() bool { return true }

func (h *revisionHook) PrePut(r record.Record) (record.Record, error) {
	submitted := r.(*revisionRecord)
	candidate := &revisionRecord{Revision: submitted.Revision + 1, target: submitted}
	candidate.SetKey(submitted.Key())
	candidate.SetMeta(submitted.Meta().Duplicate())
	return candidate, nil
}

type failingStorage struct {
	storage.InjectBase
	err error
}

func (s *failingStorage) ReadOnly() bool { return false }

func (s *failingStorage) Put(record.Record) (record.Record, error) { return nil, s.err }

type notificationRecord struct {
	record.Base
	mu               sync.Mutex
	locked           atomic.Int32
	matchedWhileOpen atomic.Bool
}

func (r *notificationRecord) Lock() {
	r.mu.Lock()
	r.locked.Add(1)
}

func (r *notificationRecord) Unlock() {
	r.locked.Add(-1)
	r.mu.Unlock()
}

func (r *notificationRecord) Meta() *record.Meta {
	if r.locked.Load() == 0 {
		r.matchedWhileOpen.Store(true)
	}
	return r.Base.Meta()
}

func (r *notificationRecord) TryLock() bool {
	if !r.mu.TryLock() {
		return false
	}
	r.locked.Add(1)
	return true
}

type notificationStorage struct {
	storage.InjectBase
	returned record.Record
}

func (s *notificationStorage) ReadOnly() bool { return false }

func (s *notificationStorage) Put(record.Record) (record.Record, error) { return s.returned, nil }

type replacementHook struct {
	HookBase
	replacement  record.Record
	err          error
	observedLock bool
}

func (h *replacementHook) UsesPrePut() bool { return true }

func (h *replacementHook) PrePut(r record.Record) (record.Record, error) {
	if locker, ok := r.(interface {
		TryLock() bool
		Unlock()
	}); ok {
		if locker.TryLock() {
			locker.Unlock()
		} else {
			h.observedLock = true
		}
	}
	if h.err != nil {
		return nil, h.err
	}
	return h.replacement, nil
}

func TestControllerPublishesTransactionalRecordOnlyAfterCommit(t *testing.T) {
	makeRecord := func() *revisionRecord {
		r := &revisionRecord{Revision: 7}
		r.SetKey("revision-transaction:profile")
		r.CreateMeta()
		return r
	}
	makeController := func(s storage.Interface, hooks ...Hook) *Controller {
		c := newController(&Database{Name: "revision-transaction"}, s, false)
		for _, hook := range hooks {
			c.hooks = append(c.hooks, &RegisteredHook{q: q.New("revision-transaction").MustBeValid(), h: hook})
		}
		return c
	}

	failed := makeRecord()
	if err := makeController(&failingStorage{err: errors.New("storage failed")}, &revisionHook{}).Put(failed); err == nil {
		t.Fatal("storage failure unexpectedly succeeded")
	}
	if failed.Revision != 7 {
		t.Fatalf("failed storage published revision %d, want 7", failed.Revision)
	}

	validationFailed := makeRecord()
	if err := makeController(&blockingStorage{entered: make(chan string, 1), release: closedChannel()}, &revisionHook{}, &rejectingPutHook{key: validationFailed.Key(), err: errors.New("validation failed")}).Put(validationFailed); err == nil {
		t.Fatal("later hook failure unexpectedly succeeded")
	}
	if validationFailed.Revision != 7 {
		t.Fatalf("failed validation published revision %d, want 7", validationFailed.Revision)
	}

	succeeded := makeRecord()
	if err := makeController(&blockingStorage{entered: make(chan string, 1), release: closedChannel()}, &revisionHook{}).Put(succeeded); err != nil {
		t.Fatalf("successful transaction: %v", err)
	}
	if succeeded.Revision != 8 {
		t.Fatalf("successful transaction revision = %d, want 8", succeeded.Revision)
	}
}

func closedChannel() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

func (h *rejectingPutHook) UsesPrePut() bool { return true }

func (h *rejectingPutHook) PrePut(r record.Record) (record.Record, error) {
	if locker, ok := r.(interface {
		TryLock() bool
		Unlock()
	}); ok {
		if locker.TryLock() {
			locker.Unlock()
		} else {
			h.observedLock = true
		}
	}
	if r.Key() == h.key {
		return nil, h.err
	}
	return r, nil
}

func TestControllerRecordWriteLocksAreBoundedAndSerialize(t *testing.T) {
	newControllerWith := func() (*Controller, *blockingStorage) {
		s := &blockingStorage{entered: make(chan string, 4), release: make(chan struct{})}
		return newController(&Database{Name: "controller-lock-test"}, s, false), s
	}

	c, s := newControllerWith()
	if got := len(c.recordWriteLocks); got != recordWriteLockStripes {
		t.Fatalf("record lock stripes = %d, want %d", got, recordWriteLockStripes)
	}
	first := NewExample("controller-lock-test:same", "first", 1)
	second := NewExample("controller-lock-test:same", "second", 2)
	first.CreateMeta()
	second.CreateMeta()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = c.Put(first) }()
	select {
	case <-s.entered:
	case <-time.After(time.Second):
		t.Fatal("first same-key write did not reach storage")
	}
	go func() { defer wg.Done(); _ = c.Put(second) }()
	select {
	case key := <-s.entered:
		t.Fatalf("same-key write entered concurrently for %s", key)
	case <-time.After(50 * time.Millisecond):
	}
	close(s.release)
	select {
	case <-s.entered:
	case <-time.After(time.Second):
		t.Fatal("second same-key write did not proceed after release")
	}
	wg.Wait()

	c, s = newControllerWith()
	firstKey, secondKey := "controller-lock-test:a", "controller-lock-test:b"
	for c.recordWriteLock(firstKey) == c.recordWriteLock(secondKey) {
		secondKey += "x"
	}
	first = NewExample(firstKey, "first", 1)
	second = NewExample(secondKey, "second", 2)
	first.CreateMeta()
	second.CreateMeta()
	wg.Add(2)
	go func() { defer wg.Done(); _ = c.Put(first) }()
	go func() { defer wg.Done(); _ = c.Put(second) }()
	for range 2 {
		select {
		case <-s.entered:
		case <-time.After(time.Second):
			t.Fatal("different-key writes did not progress independently")
		}
	}
	close(s.release)
	wg.Wait()
}

func TestPutManyDrainsAfterFailure(t *testing.T) {
	dbName := "putmany-drain-phase6"
	if _, err := Register(&Database{Name: dbName, StorageType: "hashmap"}); err != nil {
		t.Fatalf("register database: %v", err)
	}
	hookErr := errors.New("reject middle record")
	hook, err := RegisterHook(q.New(dbName).MustBeValid(), &rejectingPutHook{key: dbName + ":middle", err: hookErr})
	if err != nil {
		t.Fatalf("register hook: %v", err)
	}
	defer hook.Cancel()

	db := NewInterface(&Options{Local: true, Internal: true})
	put := db.PutMany(dbName)
	if err := put(NewExample(dbName+":first", "first", 1)); err != nil {
		t.Fatalf("submit first record: %v", err)
	}
	middle := NewExample(dbName+":middle", "middle", 2)
	if err := put(middle); err != nil && !errors.Is(err, hookErr) {
		t.Fatalf("submit middle record: %v", err)
	}
	if !middle.TryLock() {
		t.Fatal("PutMany failure left the record locked")
	}
	middle.Unlock()
	if err := put(NewExample(dbName+":after", "after", 3)); !errors.Is(err, hookErr) {
		t.Fatalf("submission after failure = %v, want hook failure", err)
	}
	if !hook.h.(*rejectingPutHook).observedLock {
		t.Fatal("PutMany hook did not receive a locked record")
	}

	finished := make(chan error, 1)
	go func() { finished <- put(nil) }()
	select {
	case err := <-finished:
		if !errors.Is(err, hookErr) {
			t.Fatalf("batch finalization = %v, want hook failure", err)
		}
	case <-time.After(time.Second):
		t.Fatal("batch finalization blocked after hook failure")
	}
	if err := put(NewExample(dbName+":later", "later", 4)); !errors.Is(err, hookErr) {
		t.Fatalf("submission after final failure = %v, want hook failure", err)
	}
}

func TestControllerPutManyLocksDirectRecordsAndPublishesUnderLock(t *testing.T) {
	dbName := "direct-putmany-lock-phase6"
	controller := newController(&Database{Name: dbName}, &blockingStorage{entered: make(chan string, 3), release: closedChannel()}, false)
	hookErr := errors.New("direct batch failure")
	hook := &rejectingPutHook{key: dbName + ":failure", err: hookErr}
	controller.hooks = append(controller.hooks, &RegisteredHook{q: q.New(dbName).MustBeValid(), h: hook}, &RegisteredHook{q: q.New(dbName).MustBeValid(), h: &revisionHook{}})

	success := &revisionRecord{Revision: 1}
	success.SetKey(dbName + ":success")
	success.CreateMeta()
	failure := NewExample(dbName+":failure", "failure", 2)
	failure.CreateMeta()
	drained := NewExample(dbName+":drained", "drained", 3)
	drained.CreateMeta()
	batch, errs := controller.PutMany()
	batch <- success
	batch <- failure
	batch <- drained
	close(batch)
	if err := <-errs; !errors.Is(err, hookErr) {
		t.Fatalf("direct batch error = %v, want %v", err, hookErr)
	}
	if !hook.observedLock || !success.publishedUnderRecordLock {
		t.Fatal("direct Controller.PutMany did not retain the record lock through hooks and transaction publication")
	}
	for _, r := range []interface {
		TryLock() bool
		Unlock()
	}{success, failure, drained} {
		if !r.TryLock() {
			t.Fatal("direct Controller.PutMany left a record locked")
		}
		r.Unlock()
	}
}

func TestPrePutReplacementLocksAreOwnedAndReleased(t *testing.T) {
	makeRecord := func(key string) *Example {
		r := NewExample(key, key, 1)
		r.CreateMeta()
		return r
	}
	makeController := func(storageInt storage.Interface, hooks ...Hook) *Controller {
		c := newController(&Database{Name: "replacement-lock"}, storageInt, false)
		for _, hook := range hooks {
			c.hooks = append(c.hooks, &RegisteredHook{q: q.New("replacement-lock").MustBeValid(), h: hook})
		}
		return c
	}

	original := makeRecord("replacement-lock:original")
	first := makeRecord("replacement-lock:original")
	second := makeRecord("replacement-lock:original")
	firstHook := &replacementHook{replacement: first}
	secondHook := &replacementHook{replacement: second}
	thirdHook := &replacementHook{replacement: second}
	original.Lock()
	if err := makeController(&blockingStorage{entered: make(chan string, 1), release: closedChannel()}, firstHook, secondHook, thirdHook).Put(original); err != nil {
		t.Fatalf("replacement chain: %v", err)
	}
	if !firstHook.observedLock || !secondHook.observedLock || !thirdHook.observedLock {
		t.Fatal("every hook did not receive its current record locked")
	}
	for _, r := range []*Example{first, second} {
		if !r.TryLock() {
			t.Fatal("controller-owned replacement remained locked")
		}
		r.Unlock()
	}
	if original.TryLock() {
		original.Unlock()
		t.Fatal("Controller.Put unlocked the caller-owned original record")
	}
	original.Unlock()

	for _, test := range []struct {
		name    string
		storage storage.Interface
		hooks   []Hook
	}{
		{
			name:    "hook failure",
			storage: &blockingStorage{entered: make(chan string, 1), release: closedChannel()},
			hooks:   []Hook{&replacementHook{replacement: makeRecord("replacement-lock:original")}, &replacementHook{err: errors.New("hook failed")}},
		},
		{
			name:    "key mismatch",
			storage: &blockingStorage{entered: make(chan string, 1), release: closedChannel()},
			hooks:   []Hook{&replacementHook{replacement: makeRecord("replacement-lock:other")}},
		},
		{
			name:    "storage failure",
			storage: &failingStorage{err: errors.New("storage failed")},
			hooks:   []Hook{&replacementHook{replacement: makeRecord("replacement-lock:original")}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := makeRecord("replacement-lock:original")
			replacement := test.hooks[0].(*replacementHook).replacement.(*Example)
			original.Lock()
			if err := makeController(test.storage, test.hooks...).Put(original); err == nil {
				t.Fatal("replacement failure unexpectedly succeeded")
			}
			if !replacement.TryLock() {
				t.Fatal("failed replacement remained locked")
			}
			replacement.Unlock()
			original.Unlock()
		})
	}
}

func TestStorageReturnedNotificationRecordIsLocked(t *testing.T) {
	returned := &notificationRecord{}
	returned.SetKey("notification-lock:returned")
	returned.CreateMeta()
	controller := newController(&Database{Name: "notification-lock"}, &notificationStorage{returned: returned}, false)
	controller.subscriptions = append(controller.subscriptions, &Subscription{
		q:        q.New("notification-lock").MustBeValid(),
		local:    true,
		internal: true,
		Feed:     make(chan record.Record, 1),
	})
	original := NewExample("notification-lock:original", "original", 1)
	original.CreateMeta()
	original.Lock()
	if err := controller.Put(original); err != nil {
		t.Fatalf("notify storage return: %v", err)
	}
	if returned.matchedWhileOpen.Load() {
		t.Fatal("subscriber matching observed an unlocked storage-returned record")
	}
	if !returned.TryLock() {
		t.Fatal("storage-returned notification record remained locked after Put")
	}
	returned.Unlock()
	if original.TryLock() {
		original.Unlock()
		t.Fatal("Controller.Put unlocked the caller-owned original during notification")
	}
	original.Unlock()
}
