package database

import (
	"errors"
	"sync"
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
	key string
	err error
}

type revisionRecord struct {
	record.Base
	sync.Mutex
	Revision uint64
	target   *revisionRecord
}

func (r *revisionRecord) CommitRecordTransaction() {
	if r.target != nil {
		r.target.Revision = r.Revision
	}
}

type revisionHook struct{ HookBase }

func (h *revisionHook) UsesPrePut() bool { return true }

func (h *revisionHook) PrePut(r record.Record) (record.Record, error) {
	submitted := r.(*revisionRecord)
	candidate := *submitted
	candidate.Revision++
	candidate.target = submitted
	return &candidate, nil
}

type failingStorage struct {
	storage.InjectBase
	err error
}

func (s *failingStorage) ReadOnly() bool { return false }

func (s *failingStorage) Put(record.Record) (record.Record, error) { return nil, s.err }

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
	if err := put(NewExample(dbName+":middle", "middle", 2)); err != nil && !errors.Is(err, hookErr) {
		t.Fatalf("submit middle record: %v", err)
	}
	if err := put(NewExample(dbName+":after", "after", 3)); !errors.Is(err, hookErr) {
		t.Fatalf("submission after failure = %v, want hook failure", err)
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
