package server

import (
	"bytes"
	"encoding/base64"
	"html/template"
	"net/http"
	"time"

	"github.com/kuberoam/roam-gate/internal/msg"
)

// The only pages Gate serves: sign-in and its outcome. Everything else is
// managed from Roam through the API. No JavaScript, no external assets.

var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="{{.Lang}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}} · Roam Gate</title>
<style>
:root{color-scheme:light dark;--bg:#0f172a;--card:#1e293b;--line:#334155;--text:#f8fafc;--muted:#94a3b8;--accent:#22c55e;--red:#f87171}
@media (prefers-color-scheme:light){:root{--bg:#f1f5f9;--card:#fff;--line:#e2e8f0;--text:#0f172a;--muted:#475569}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;padding:16px}
.card{width:100%;max-width:440px;background:var(--card);border:1px solid var(--line);border-radius:16px;padding:28px}
.brand{display:flex;align-items:center;gap:10px;font-weight:800;font-size:18px;margin-bottom:18px}
.dot{width:26px;height:26px;border-radius:8px;background:var(--accent)}
h1{font-size:20px;margin:0 0 6px}p{color:var(--muted);margin:0 0 18px}
a.btn,button{display:block;width:100%;text-align:center;padding:11px 14px;border-radius:10px;border:1px solid var(--line);background:transparent;color:var(--text);font:inherit;font-weight:600;text-decoration:none;cursor:pointer;margin-top:10px}
a.btn:hover,button:hover{border-color:var(--accent)}button.primary,a.primary{background:var(--accent);border-color:var(--accent);color:#052e16}
label{display:block;font-size:13px;color:var(--muted);margin-top:12px}input{width:100%;padding:10px 12px;border-radius:10px;border:1px solid var(--line);background:transparent;color:var(--text);font:inherit;margin-top:4px}
details{margin-top:14px}summary{cursor:pointer;color:var(--muted)}pre{white-space:pre-wrap;word-break:break-all;font:12px/1.5 ui-monospace,Menlo,monospace;background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:12px;max-height:260px;overflow:auto}
.err{color:var(--red)}.small{font-size:13px;color:var(--muted);margin-top:14px}
</style></head><body><main class="card"><div class="brand"><span class="dot"></span>Roam Gate</div>{{.Body}}</main></body></html>`))

// view renders pages in one language.
type view struct{ lang string }

func viewFor(r *http.Request) view { return view{msg.Lang(r)} }

// T is the template helper: {{call $.T "page.signInWith" "provider" .Name}}.
func (v view) T(code string, kv ...string) string { return msg.T(v.lang, msg.Code(code), kv...) }

func (s *Server) page(w http.ResponseWriter, v view, code int, title msg.Code, body template.HTML) {
	var buf bytes.Buffer
	if err := pageTmpl.Execute(&buf, map[string]any{"Lang": v.lang, "Title": v.T(string(title)), "Body": body}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	w.Write(buf.Bytes())
}

func render(t *template.Template, data any) template.HTML {
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return template.HTML(template.HTMLEscapeString(err.Error()))
	}
	return template.HTML(buf.String()) //nolint:gosec // produced by html/template
}

var loginTmpl = template.Must(template.New("login").Parse(`<h1>{{call .T "page.titleSignIn"}}</h1>
<p>{{call .T "page.signInIntro"}}</p>
{{if .Req}}<p class="small">{{call .T "page.appRequest"}}</p>{{end}}
{{if not .Providers}}<p class="err">{{call .T "page.noProviders"}}</p>{{end}}
{{range .Providers}}{{if .Password}}
<form method="post" action="/auth/{{.ID}}/login">
<input type="hidden" name="t" value="{{$.Token}}"><input type="hidden" name="req" value="{{$.Req}}">
<label>{{call $.T "page.username" "provider" .Name}}<input name="username" autocomplete="username" required></label>
<label>{{call $.T "page.password"}}<input name="password" type="password" autocomplete="current-password" required></label>
<button class="primary" type="submit">{{call $.T "page.signInWith" "provider" .Name}}</button></form>
{{else}}<a class="btn" href="/auth/{{.ID}}/start?req={{$.Req}}">{{call $.T "page.continueWith" "provider" .Name}}</a>{{end}}{{end}}`))

func loginBody(v view, ps []providerView, req, token string) template.HTML {
	return render(loginTmpl, map[string]any{"T": v.T, "Providers": ps, "Req": req, "Token": token})
}

var errorTmpl = template.Must(template.New("error").Parse(`<h1>{{call .T "page.errorHeading"}}</h1><p class="err">{{.Message}}</p><a class="btn" href="/login">{{call .T "page.back"}}</a>`))

// errorBody shows err in the page's language.
func errorBody(v view, err error) template.HTML {
	return render(errorTmpl, map[string]any{"T": v.T, "Message": msg.Localize(v.lang, err)})
}

var kubeconfigTmpl = template.Must(template.New("kubeconfig").Parse(`<h1>{{call .T "page.signedInHeading"}}</h1>
<p>{{call .T "page.signedInAs" "user" .User}} {{call .T "page.accessUntil" "expires" .Expires}}</p>
<a class="btn primary" download="kubeconfig-roam-gate.yaml" href="{{.Href}}">{{call .T "page.download"}}</a>
<details><summary>{{call .T "page.showKubeconfig"}}</summary><pre>{{.YAML}}</pre></details>
<p class="small">{{call .T "page.kubeconfigHint"}}</p>`))

func kubeconfigBody(v view, user string, expires time.Time, yaml string) template.HTML {
	href := template.URL("data:application/yaml;base64," + base64.StdEncoding.EncodeToString([]byte(yaml))) //nolint:gosec // our own content
	return render(kubeconfigTmpl, map[string]any{"T": v.T, "User": user, "Expires": expires.UTC().Format("2006-01-02 15:04 UTC"), "YAML": yaml, "Href": href})
}
