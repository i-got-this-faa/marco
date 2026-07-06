package cache

import (
	"testing"
	"time"
)

func TestCacheGetSet(t *testing.T) {
	c := New[string, int](time.Second, 10)
	c.Set("a", 1)
	v, ok := c.Get("a")
	if !ok {
		t.Fatal("expected found")
	}
	if v != 1 {
		t.Fatalf("got %d, want 1", v)
	}
}

func TestCacheGetMissing(t *testing.T) {
	c := New[string, int](time.Second, 10)
	_, ok := c.Get("nonexistent")
	if ok {
		t.Fatal("expected not found")
	}
}

func TestCacheExpiry(t *testing.T) {
	c := New[string, int](50*time.Millisecond, 10)
	c.Set("a", 1)
	time.Sleep(100 * time.Millisecond)
	_, ok := c.Get("a")
	if ok {
		t.Fatal("expected expired entry to be gone")
	}
}

func TestCacheNoExpiry(t *testing.T) {
	c := New[string, int](0, 10)
	c.Set("a", 1)
	_, ok := c.Get("a")
	if !ok {
		t.Fatal("expected entry with no expiry to be found")
	}
}

func TestCacheDelete(t *testing.T) {
	c := New[string, int](time.Second, 10)
	c.Set("a", 1)
	c.Delete("a")
	_, ok := c.Get("a")
	if ok {
		t.Fatal("expected deleted entry to be gone")
	}
}

func TestCacheClear(t *testing.T) {
	c := New[string, int](time.Second, 10)
	c.Set("a", 1)
	c.Set("b", 2)
	c.Clear()
	if c.Len() != 0 {
		t.Fatal("expected empty cache after clear")
	}
}

func TestCacheMaxSizeEviction(t *testing.T) {
	c := New[string, int](time.Second, 3)
	c.Set("a", 1)
	c.Set("b", 2)
	c.Set("c", 3)
	c.Set("d", 4) // should evict one
	if c.Len() != 3 {
		t.Fatalf("expected 3 entries after eviction, got %d", c.Len())
	}
}

func TestCacheMaxSizeUnlimited(t *testing.T) {
	c := New[string, int](time.Second, 0)
	for i := 0; i < 1000; i++ {
		c.Set(string(rune('a'+i%26)), i)
	}
	// Should not evict anything
	if c.Len() != 26 {
		t.Fatalf("expected 26 unique keys, got %d", c.Len())
	}
}

func TestCacheConcurrent(t *testing.T) {
	c := New[int, int](time.Second, 100)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			c.Set(i, i)
		}
		close(done)
	}()
	for i := 0; i < 100; i++ {
		c.Get(i)
	}
	<-done
}
