// Package audit records what people do through Gate: every event goes to the
// database (for Roam's audit view) and to stdout as a JSON line (for Loki,
// Elasticsearch or a SIEM).
//
// Writes are batched off the request path; the proxy never waits on disk
// unless the queue is full, in which case the event is written directly
// rather than dropped — an audit trail with gaps is useless for investigations.
package audit

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/kuberoam/roam-gate/internal/store"
)

type Recorder struct {
	st    *store.Store
	out   io.Writer
	queue chan *store.Event
	mu    sync.Mutex // serialises stdout lines
	done  chan struct{}
}

// New starts the background writer; out receives one JSON line per event (nil to skip).
func New(st *store.Store, out io.Writer) *Recorder {
	r := &Recorder{st: st, out: out, queue: make(chan *store.Event, 4096), done: make(chan struct{})}
	go r.loop()
	return r
}

// Record queues an event.
func (r *Recorder) Record(e *store.Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	if r.out != nil {
		line, _ := json.Marshal(struct {
			Audit *store.Event `json:"audit"`
		}{e})
		r.mu.Lock()
		r.out.Write(append(line, '\n'))
		r.mu.Unlock()
	}
	select {
	case r.queue <- e:
	default:
		if err := r.write([]*store.Event{e}); err != nil {
			slog.Error("audit write failed", "err", err)
		}
	}
}

func (r *Recorder) write(batch []*store.Event) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return r.st.InsertEvents(ctx, batch)
}

func (r *Recorder) loop() {
	defer close(r.done)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var batch []*store.Event
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := r.write(batch); err != nil {
			slog.Error("audit write failed", "err", err, "events", len(batch))
		}
		batch = batch[:0]
	}
	for {
		select {
		case e, ok := <-r.queue:
			if !ok {
				flush()
				return
			}
			batch = append(batch, e)
			if len(batch) >= 256 {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

// Close writes what is queued; call on shutdown.
func (r *Recorder) Close() {
	close(r.queue)
	<-r.done
}
