package auth

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/kuberoam/roam-gate/internal/identity"
	"github.com/kuberoam/roam-gate/internal/store"
)

func TestStartAddsLocalGroups(t *testing.T) {
	st, err := store.Open(t.TempDir(), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	id := &identity.Identity{Provider: "github", Email: "alice@corp.com", Login: "alice"}
	if err := st.SetLocalGroupMember(ctx, "developer", id.UserID(), "admin@corp.com", true); err != nil {
		t.Fatal(err)
	}
	s := NewSessions(st, time.Hour, "", nil, nil)
	_, sess, err := s.Start(ctx, id, "1.2.3.4", "test-agent")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(sess.Groups, identity.LocalGroupID("developer")) {
		t.Fatalf("local group missing from session: %v", sess.Groups)
	}
	// Someone in no local group gets none of them.
	_, sess2, err := s.Start(ctx, &identity.Identity{Provider: "github", Email: "bob@corp.com", Login: "bob"}, "1.2.3.4", "test-agent")
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(sess2.Groups, identity.LocalGroupID("developer")) {
		t.Fatalf("group leaked to another user: %v", sess2.Groups)
	}
}
