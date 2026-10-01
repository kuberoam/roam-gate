// Package msg holds every message Gate shows to people — sign-in pages, API
// errors, binding statuses — as a stable code with parameters, rendered in the
// caller's language (Accept-Language). Roam sends its UI language, so what it
// shows comes back translated; logs and operator errors stay in English.
//
// Adding a language: copy en.go to <lang>.go, translate the values (missing
// codes fall back to English) and register it in catalogs.
package msg

import (
	"errors"
	"net/http"
	"strings"
)

// Code names a message.
type Code string

// DefaultLang is used when the caller's language isn't available.
const DefaultLang = "en"

var catalogs = map[string]map[Code]string{"en": en, "vi": vi}

// Error is an error with a translatable message.
type Error struct {
	Code   Code
	Params map[string]string
	Err    error // the cause, if any; shown as {error}
}

func (e *Error) Error() string { return e.Text(DefaultLang) }
func (e *Error) Unwrap() error { return e.Err }

// Text renders the message in lang.
func (e *Error) Text(lang string) string { return render(lang, e.Code, e.Params) }

// New makes an error from a code and key/value parameters.
func New(code Code, kv ...string) *Error { return &Error{Code: code, Params: pairs(kv)} }

// Wrap makes an error from a code whose {error} parameter is cause.
func Wrap(code Code, cause error, kv ...string) *Error {
	p := pairs(kv)
	if cause != nil {
		p["error"] = Localize(DefaultLang, cause)
	}
	return &Error{Code: code, Params: p, Err: cause}
}

// T renders a message in lang.
func T(lang string, code Code, kv ...string) string { return render(lang, code, pairs(kv)) }

// Localize renders err in lang: translated when it is (or wraps) an *Error,
// as is otherwise.
func Localize(lang string, err error) string {
	var e *Error
	if errors.As(err, &e) {
		if e.Err != nil {
			// Re-render the cause too, so a wrapped message is translated all the way down.
			p := make(map[string]string, len(e.Params))
			for k, v := range e.Params {
				p[k] = v
			}
			p["error"] = Localize(lang, e.Err)
			return render(lang, e.Code, p)
		}
		return e.Text(lang)
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

// CodeOf is the code of err, or "" when it has none.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Lang picks the best supported language from the request's Accept-Language.
func Lang(r *http.Request) string {
	for _, part := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		tag := strings.ToLower(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]))
		if _, ok := catalogs[tag]; ok {
			return tag
		}
		if base, _, _ := strings.Cut(tag, "-"); base != "" {
			if _, ok := catalogs[base]; ok {
				return base
			}
		}
	}
	return DefaultLang
}

func pairs(kv []string) map[string]string {
	p := make(map[string]string, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		p[kv[i]] = kv[i+1]
	}
	return p
}

func render(lang string, code Code, params map[string]string) string {
	tmpl, ok := catalogs[lang][code]
	if !ok {
		if tmpl, ok = en[code]; !ok {
			return string(code)
		}
	}
	if len(params) == 0 {
		return tmpl
	}
	r := make([]string, 0, 2*len(params))
	for k, v := range params {
		r = append(r, "{"+k+"}", v)
	}
	return strings.NewReplacer(r...).Replace(tmpl)
}

// Missing lists codes a language lacks (for tests).
func Missing(lang string) []string {
	var out []string
	for c := range en {
		if _, ok := catalogs[lang][c]; !ok {
			out = append(out, string(c))
		}
	}
	return out
}
