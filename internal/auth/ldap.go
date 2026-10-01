package auth

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/kuberoam/roam-gate/internal/identity"
	"github.com/kuberoam/roam-gate/internal/msg"
	"github.com/kuberoam/roam-gate/internal/store"
)

// LDAPConfig configures LDAP / Active Directory sign-in: Gate looks the user
// up with a service account, binds as them to check the password, then reads
// their groups.
type LDAPConfig struct {
	URL                string `json:"url"` // ldaps://ldap.corp:636 or ldap://…
	StartTLS           bool   `json:"startTLS,omitempty"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify,omitempty"`
	BindDN             string `json:"bindDN"`
	BindPassword       string `json:"bindPassword"`
	UserBaseDN         string `json:"userBaseDN"`
	UserFilter         string `json:"userFilter,omitempty"` // default (uid={username}); AD: (sAMAccountName={username})
	UsernameAttr       string `json:"usernameAttr,omitempty"`
	EmailAttr          string `json:"emailAttr,omitempty"`
	NameAttr           string `json:"nameAttr,omitempty"`
	GroupBaseDN        string `json:"groupBaseDN,omitempty"`
	GroupFilter        string `json:"groupFilter,omitempty"` // default (member={dn})
	GroupNameAttr      string `json:"groupNameAttr,omitempty"`
	Restrictions
}

type ldapProvider struct {
	info *store.Provider
	cfg  LDAPConfig
}

func newLDAP(sp *store.Provider, c LDAPConfig) (*ldapProvider, error) {
	if c.URL == "" || c.UserBaseDN == "" {
		return nil, msg.New(msg.ProviderRequired, "fields", "url, userBaseDN")
	}
	def := func(p *string, v string) {
		if *p == "" {
			*p = v
		}
	}
	def(&c.UserFilter, "(uid={username})")
	def(&c.UsernameAttr, "uid")
	def(&c.EmailAttr, "mail")
	def(&c.NameAttr, "cn")
	def(&c.GroupFilter, "(member={dn})")
	def(&c.GroupNameAttr, "cn")
	return &ldapProvider{info: sp, cfg: c}, nil
}

func (l *ldapProvider) Info() *store.Provider { return l.info }

func (l *ldapProvider) dial() (*ldap.Conn, error) {
	tlsCfg := &tls.Config{InsecureSkipVerify: l.cfg.InsecureSkipVerify} //nolint:gosec // opt-in for lab directories
	conn, err := ldap.DialURL(l.cfg.URL, ldap.DialWithTLSConfig(tlsCfg), ldap.DialWithDialer(&net.Dialer{Timeout: ldapTimeout}))
	if err != nil {
		return nil, err
	}
	conn.SetTimeout(ldapTimeout) // a hung directory must not hold sign-in pages open
	if l.cfg.StartTLS {
		if err := conn.StartTLS(tlsCfg); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

const ldapTimeout = 10 * time.Second

var errBadCredentials = msg.New(msg.BadCredentials)

func (l *ldapProvider) Login(ctx context.Context, username, password string) (*identity.Identity, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil, errBadCredentials // an empty password would be an anonymous bind
	}
	conn, err := l.dial()
	if err != nil {
		return nil, msg.Wrap(msg.LDAPConnect, err)
	}
	defer conn.Close()
	if l.cfg.BindDN != "" {
		if err := conn.Bind(l.cfg.BindDN, l.cfg.BindPassword); err != nil {
			return nil, msg.Wrap(msg.LDAPServiceAccount, err)
		}
	}
	filter := strings.ReplaceAll(l.cfg.UserFilter, "{username}", ldap.EscapeFilter(username))
	res, err := conn.Search(ldap.NewSearchRequest(l.cfg.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 10, false,
		filter, []string{l.cfg.UsernameAttr, l.cfg.EmailAttr, l.cfg.NameAttr}, nil))
	if err != nil {
		return nil, msg.Wrap(msg.LDAPSearch, err)
	}
	if len(res.Entries) != 1 {
		return nil, errBadCredentials
	}
	entry := res.Entries[0]
	if err := conn.Bind(entry.DN, password); err != nil {
		return nil, errBadCredentials
	}
	id := &identity.Identity{Provider: l.info.ID, Subject: entry.DN, Login: entry.GetAttributeValue(l.cfg.UsernameAttr),
		Email: entry.GetAttributeValue(l.cfg.EmailAttr), Name: entry.GetAttributeValue(l.cfg.NameAttr)}
	if id.Login == "" {
		id.Login = username
	}
	if l.cfg.GroupBaseDN != "" {
		// Search groups as the service account again (users often can't).
		if l.cfg.BindDN != "" {
			if err := conn.Bind(l.cfg.BindDN, l.cfg.BindPassword); err != nil {
				return nil, msg.Wrap(msg.LDAPServiceAccount, err)
			}
		}
		gf := strings.NewReplacer("{dn}", ldap.EscapeFilter(entry.DN), "{username}", ldap.EscapeFilter(id.Login)).Replace(l.cfg.GroupFilter)
		gres, err := conn.Search(ldap.NewSearchRequest(l.cfg.GroupBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1000, 10, false,
			gf, []string{l.cfg.GroupNameAttr}, nil))
		if err != nil {
			return nil, msg.Wrap(msg.LDAPSearch, err)
		}
		for _, g := range gres.Entries {
			if n := g.GetAttributeValue(l.cfg.GroupNameAttr); n != "" {
				id.Groups = append(id.Groups, n)
			}
		}
	}
	if err := l.cfg.Restrictions.Check(id); err != nil {
		return nil, err
	}
	return id, nil
}
