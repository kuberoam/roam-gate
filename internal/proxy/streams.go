package proxy

import (
	"context"
	"sync"
	"time"
)

// A request is authenticated when it starts, but a watch, a log stream or an
// exec session can last for hours: without this it would outlive the session
// that opened it, so signing someone out wouldn't stop what they have open.
// Each request runs until its session expires (a context deadline); Run cuts
// the ones whose session was revoked meanwhile. The client sees the
// connection end, reconnects, and is told it isn't signed in.

const streamSweep = 5 * time.Second

type stream struct {
	session string
	cancel  context.CancelFunc
}

type streams struct {
	mu   sync.Mutex
	live map[*stream]struct{}
}

func (s *streams) add(session string, cancel context.CancelFunc) *stream {
	st := &stream{session: session, cancel: cancel}
	s.mu.Lock()
	if s.live == nil {
		s.live = map[*stream]struct{}{}
	}
	s.live[st] = struct{}{}
	s.mu.Unlock()
	return st
}

func (s *streams) remove(st *stream) {
	s.mu.Lock()
	delete(s.live, st)
	s.mu.Unlock()
}

// sweep cuts the requests of sessions that are no longer live.
func (s *streams) sweep(ctx context.Context, live func(context.Context, string) bool) {
	s.mu.Lock()
	bySession := map[string][]*stream{}
	for st := range s.live {
		bySession[st.session] = append(bySession[st.session], st)
	}
	s.mu.Unlock()
	for id, list := range bySession {
		if live(ctx, id) || ctx.Err() != nil {
			continue
		}
		for _, st := range list {
			st.cancel()
		}
	}
}

// Run keeps open requests in line with their sessions until ctx ends.
func (p *Proxy) Run(ctx context.Context) {
	t := time.NewTicker(streamSweep)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.open.sweep(ctx, p.sessions.Live)
			if p.granted != nil {
				if v, ok := p.granted.Version(); ok {
					p.memo.prune(v)
				}
			}
		}
	}
}
