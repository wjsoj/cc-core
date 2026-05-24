package ratelimit

import (
	"sync"
	"testing"
	"time"
)

func TestRPMAllowWithinLimit(t *testing.T) {
	var l RPM
	for i := 0; i < 5; i++ {
		ok, retry := l.Allow("k", 5)
		if !ok {
			t.Fatalf("call %d: expected ok, got reject (retry=%d)", i, retry)
		}
	}
	ok, retry := l.Allow("k", 5)
	if ok {
		t.Fatal("6th call should be rejected")
	}
	if retry < 1 {
		t.Fatalf("retry should be >=1, got %d", retry)
	}
}

func TestRPMZeroLimitDisabled(t *testing.T) {
	var l RPM
	for i := 0; i < 1000; i++ {
		ok, _ := l.Allow("k", 0)
		if !ok {
			t.Fatal("limit=0 should always allow")
		}
	}
}

func TestRPMIndependentKeys(t *testing.T) {
	var l RPM
	for i := 0; i < 3; i++ {
		l.Allow("a", 3)
	}
	if ok, _ := l.Allow("a", 3); ok {
		t.Fatal("a should be saturated")
	}
	// b is untouched.
	if ok, _ := l.Allow("b", 3); !ok {
		t.Fatal("b should still have capacity")
	}
}

func TestConcurrencyBeginEnd(t *testing.T) {
	var c Concurrency
	cur1, end1 := c.Begin("k")
	if cur1 != 1 {
		t.Fatalf("first Begin should be 1, got %d", cur1)
	}
	cur2, end2 := c.Begin("k")
	if cur2 != 2 {
		t.Fatalf("second Begin should be 2, got %d", cur2)
	}
	if c.Snapshot("k") != 2 {
		t.Fatalf("Snapshot=%d want 2", c.Snapshot("k"))
	}
	end1()
	if c.Snapshot("k") != 1 {
		t.Fatalf("after one end Snapshot=%d want 1", c.Snapshot("k"))
	}
	end2()
	if c.Snapshot("k") != 0 {
		t.Fatalf("after both end Snapshot=%d want 0", c.Snapshot("k"))
	}
}

func TestConcurrencyEndIdempotent(t *testing.T) {
	var c Concurrency
	_, end := c.Begin("k")
	end()
	end() // should be no-op
	end()
	if c.Snapshot("k") != 0 {
		t.Fatalf("double end caused underflow: %d", c.Snapshot("k"))
	}
}

func TestConcurrencyConcurrent(t *testing.T) {
	var c Concurrency
	var wg sync.WaitGroup
	const N = 100
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			_, end := c.Begin("hot")
			time.Sleep(time.Millisecond)
			end()
		}()
	}
	wg.Wait()
	if c.Snapshot("hot") != 0 {
		t.Fatalf("Snapshot=%d after parallel begin/end", c.Snapshot("hot"))
	}
}
