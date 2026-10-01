package msg

import (
	"errors"
	"net/http/httptest"
	"testing"
)

func TestCatalogsAreComplete(t *testing.T) {
	for lang := range catalogs {
		if m := Missing(lang); len(m) > 0 {
			t.Errorf("%s lacks %v", lang, m)
		}
	}
}

func TestLocalize(t *testing.T) {
	err := Wrap(LDAPConnect, New(BadCredentials))
	if got := Localize("vi", err); got != "Không kết nối được LDAP: Sai tên đăng nhập hoặc mật khẩu." {
		t.Fatal(got)
	}
	if got := Localize("en", errors.New("plain")); got != "plain" {
		t.Fatal(got)
	}
	if got := T("xx", NamespaceMissing, "namespace", "prod"); got != "Namespace prod doesn't exist." {
		t.Fatal(got)
	}
}

func TestLang(t *testing.T) {
	for header, want := range map[string]string{"vi-VN,vi;q=0.9,en;q=0.8": "vi", "fr-FR, en;q=0.5": "en", "": "en", "VI": "vi"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Accept-Language", header)
		if got := Lang(r); got != want {
			t.Errorf("%q → %s, want %s", header, got, want)
		}
	}
}
