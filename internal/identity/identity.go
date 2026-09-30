// Package identity names Gate's users and groups, in Gate and in Kubernetes.
//
// In Gate a user is their verified email (alice@corp.com), or "<provider>:<login>"
// when the provider has no verified email; a group is "<provider>:<group>".
// In Kubernetes both get the "roam:" prefix, so they can never collide with
// the cluster's own users, groups or cloud identities.
package identity

import "strings"

const (
	KubePrefix = "roam:"
	// Authenticated is the group every Gate user is in.
	Authenticated = "authenticated"
)

// Identity is who a provider says someone is.
type Identity struct {
	Provider string   // provider ID
	Subject  string   // the provider's stable ID for them
	Login    string   // username at the provider
	Email    string   // verified email, if any
	Name     string   // display name
	Groups   []string // group names at the provider
}

// UserID is the Gate user ID for an identity.
func (i *Identity) UserID() string {
	if i.Email != "" {
		return strings.ToLower(i.Email)
	}
	return i.Provider + ":" + strings.ToLower(i.Login)
}

// GroupIDs are the identity's groups as Gate group IDs, plus "authenticated".
func (i *Identity) GroupIDs() []string {
	out := make([]string, 0, len(i.Groups)+1)
	seen := map[string]bool{}
	for _, g := range i.Groups {
		id := i.Provider + ":" + g
		if g != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return append(out, Authenticated)
}

// KubeUser is the Kubernetes user name Gate impersonates.
func KubeUser(userID string) string { return KubePrefix + userID }

// KubeGroup is the Kubernetes group name for a Gate group ID.
func KubeGroup(groupID string) string { return KubePrefix + groupID }

// KubeGroups maps Gate group IDs to Kubernetes groups.
func KubeGroups(groupIDs []string) []string {
	out := make([]string, len(groupIDs))
	for i, g := range groupIDs {
		out[i] = KubeGroup(g)
	}
	return out
}
