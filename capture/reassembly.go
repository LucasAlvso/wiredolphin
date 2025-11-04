package capture

import (
	"fmt"
	"sync"
	"time"

	"wiredolphin/parser"
)

// fragmentKey identifies a fragmented datagram for reassembly
type fragmentKey struct {
	src string
	dst string
	id  uint32
}

type fragEntry struct {
	received map[uint32][]byte // offset -> data
	total    uint32            // expected total length, 0 if unknown
	proto    uint8
	created  time.Time
}

// ReassemblyTable manages IPv6 fragment reassembly
type ReassemblyTable struct {
	mu    sync.Mutex
	table map[fragmentKey]*fragEntry
	ttl   time.Duration
}

// NewReassemblyTable creates a new table and starts a cleanup goroutine
func NewReassemblyTable(ttl time.Duration) *ReassemblyTable {
	r := &ReassemblyTable{
		table: make(map[fragmentKey]*fragEntry),
		ttl:   ttl,
	}
	go r.cleanupLoop()
	return r
}

func (r *ReassemblyTable) cleanupLoop() {
	ticker := time.NewTicker(r.ttl / 2)
	for range ticker.C {
		r.mu.Lock()
		now := time.Now()
		for k, e := range r.table {
			if now.Sub(e.created) > r.ttl {
				delete(r.table, k)
			}
		}
		r.mu.Unlock()
	}
}

// AddFragment adds a fragment and attempts to assemble. Returns assembled payload and proto when complete.
func (r *ReassemblyTable) AddFragment(src, dst string, frag *parser.IPv6Fragment) ([]byte, uint8, bool, error) {
	key := fragmentKey{src: src, dst: dst, id: frag.ID}

	r.mu.Lock()
	defer r.mu.Unlock()

	e, ok := r.table[key]
	if !ok {
		e = &fragEntry{received: make(map[uint32][]byte), proto: frag.NextHeader, created: time.Now()}
		r.table[key] = e
	}

	// store fragment data
	offset := uint32(frag.Offset) * 8
	e.received[offset] = frag.Data

	// if this fragment has More==false, we can compute expected total length
	if !frag.More {
		// last fragment: total length = offset + len(data)
		e.total = offset + uint32(len(frag.Data))
	}

	// if we know total, see if we have all bytes
	if e.total == 0 {
		return nil, 0, false, nil
	}

	// attempt to assemble
	assembled := make([]byte, e.total)
	var written uint32
	// iterate fragments; small optimization: we don't guarantee ordering, just copy
	for off, d := range e.received {
		if off+uint32(len(d)) > e.total {
			return nil, 0, false, fmt.Errorf("fragment exceeds expected total length")
		}
		copy(assembled[off:off+uint32(len(d))], d)
		written += uint32(len(d))
	}

	if written < e.total {
		return nil, 0, false, nil
	}

	// assembled complete, remove entry
	delete(r.table, key)
	return assembled, e.proto, true, nil
}
