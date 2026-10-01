package audit

import (
	"context"
	"testing"

	"github.com/kuberoam/roam-gate/internal/store"
)

// An exec session that ends after shutdown still gets recorded, and never panics.
func TestRecordAfterClose(t *testing.T) {
	st, err := store.Open(t.TempDir(), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	r := New(st, nil)
	r.Record(&store.Event{Kind: store.KindRequest, Verb: "get"})
	r.Close()
	r.Close()
	r.Record(&store.Event{Kind: store.KindRequest, Verb: "create", Subresource: "exec"})
	events, err := st.Audit(context.Background(), store.AuditQuery{})
	if err != nil || len(events) != 2 {
		t.Fatalf("events: %v %d", err, len(events))
	}
}
