# Roam Gate

Lightweight access control for Kubernetes: **SSO sign-in, per-user and per-group permissions, and an audit trail of what people did** — in one small pod with no CRDs, webhooks or agents.

Roam Gate is the access-control service behind [Roam](https://github.com/kuberoam/kuberoam)'s *Access control* screen, but it is a standalone, open-source service: install it with Helm and drive it from Roam, `kubectl` or its HTTP API.

|                | Roam Gate |
| -------------- | --------- |
| Footprint      | 1 pod, ~40 MiB RAM, ~60 MB image (distroless, static Go) |
| Storage        | SQLite on a small volume |
| Sign-in        | GitHub (incl. Enterprise), GitLab (incl. self-hosted), Google, any OpenID Connect provider (Keycloak, Okta, Entra ID, Authentik, Gitea/Forgejo…), LDAP / Active Directory |
| Permissions    | Kubernetes RBAC — Gate writes RoleBindings / ClusterRoleBindings for users and groups |
| Audit          | Changes, exec / attach / port-forward, Secret access, denied requests (or every request), sign-ins and admin changes — with filters and retention |
| Clouds         | EKS (aws-auth IAM mappings), GKE (Google users/groups), AKS (Entra ID objects) |

## How it works

```
 kubectl / Roam ──token──▶ Roam Gate /k8s ──Impersonate-User/Group──▶ kube-apiserver
                               │                                          │
                        sign-in (SSO)                              RBAC decides
                        audit trail (SQLite)            (RoleBindings written by Gate)
```

1. People sign in with SSO. Gate issues a session token (`rg_…`) and a kubeconfig whose server is `https://<gate>/k8s`; its context is named `<clusterName>-roam-gate`, so merging it into `~/.kube/config` doesn't clash with a context people already have for the same cluster.
2. Gate authenticates each request and forwards it to the API server as the person, using impersonation: user `roam:<id>`, groups `roam:<provider>:<group>` and `roam:authenticated`. Anything the client sends to impersonate someone else is dropped.
3. The API server's own RBAC decides. Gate turns its *bindings* ("group `github:acme/devs` gets `edit` in `staging`") into RoleBindings / ClusterRoleBindings labelled `kuberoam.dev/managed-by=roam-gate`, and keeps them in shape: it watches only its own objects (by label), so an edit by hand or a deletion is undone within a second; deleting a binding removes its objects; nothing else is touched.
4. Every request worth investigating is recorded, together with sign-ins, session revocations and admin changes (with before/after).

Identity naming: a user is their verified email (lowercase), or `<provider>:<login>` when there is none. Groups are `<provider>:<group>` — e.g. `github:acme` (org), `github:acme/platform` (team), `gitlab:infra/sre`, `ldap:k8s-admins`.

## Install

```sh
helm install roam-gate oci://ghcr.io/kuberoam/charts/roam-gate \
  --namespace roam-system --create-namespace \
  --set externalURL=https://gate.example.com
```

Or let Roam do it: *Access control → Install Gate*.

Common settings (see [`values.yaml`](chart/roam-gate/values.yaml)):

| Value | Default | |
| ----- | ------- | - |
| `externalURL` | `https://<ingress.host>` or `https://localhost:8443` | How people reach Gate (sign-in pages, kubeconfigs) |
| `ingress.enabled`, `ingress.host`, `ingress.className`, `ingress.tlsSecretName` | off | Expose Gate through an Ingress |
| `ingress.checkClass` | `true` | Fail the install when no IngressClass would serve the Ingress (no `className` and no default class, or a class the cluster doesn't have) |
| `service.type` | `ClusterIP` | `LoadBalancer` to expose it directly |
| `tls.mode` | `selfSigned` | `selfSigned` (CA embedded in kubeconfigs), `secret` (an existing TLS Secret), `certManager` (issued from `tls.issuer`), `none` (TLS at the Ingress) |
| `tls.issuer.kind`, `tls.issuer.name` | `ClusterIssuer`, – | cert-manager Issuer or ClusterIssuer for `tls.mode=certManager`; `tls.secretHasCA` puts a private CA in kubeconfigs |
| `ingress.issuer.kind`, `ingress.issuer.name` | `ClusterIssuer`, – | cert-manager issues the Ingress certificate (into `ingress.tlsSecretName`, or `<release>-ingress-tls`) |
| `admins.users` / `admins.groups` | – | Who may administer Gate after SSO is set up |
| `audit.level` | `writes` | `writes` or `all` (reads too) |
| `audit.retention` | `30d` | Older events are pruned hourly |
| `session.ttl` | `12h` | Session lifetime |
| `persistence.size` | `20Gi` | The database, audit trail included; kept on uninstall (`persistence.keep`) |
| `eks.awsAuth` | `false` | Allow Gate to add its own entries to the `aws-auth` ConfigMap |

Values are checked against [`values.schema.json`](chart/roam-gate/values.schema.json) (unknown keys, enums, durations, sizes).

Without an Ingress or LoadBalancer, reach Gate with `kubectl -n roam-system port-forward svc/roam-gate 8443:443`.

The chart generates a secret key and a bootstrap admin token (kept across upgrades):

```sh
kubectl -n roam-system get secret roam-gate-secrets -o jsonpath='{.data.admin-token}' | base64 -d
```

### What Gate may do in your cluster

Gate's ClusterRole lets it **impersonate** users and groups, **manage RoleBindings / ClusterRoleBindings** and **bind ClusterRoles**, and list namespaces and ClusterRoles. That is powerful — whoever administers Gate can grant any role — so protect the admin token and choose `admins.*` carefully. Gate only ever changes bindings it created.

## Sign-in providers

Register an OAuth app / client at the provider with the callback URL `https://<gate>/auth/<provider-id>/callback`, then add the provider (from Roam, or `POST /api/v1/providers`):

```json
{ "id": "github", "type": "github", "name": "GitHub", "enabled": true,
  "config": { "clientId": "…", "clientSecret": "…", "allowedOrgs": ["acme"] } }
```

| Type | Config | Scopes Gate asks for |
| ---- | ------ | -------------------- |
| `github` | `clientId`, `clientSecret`, `url` (GitHub Enterprise Server), `allowedOrgs` — groups: orgs and `org/team` | `read:user`, `user:email`, `read:org` (OAuth apps take any; an organization that restricts OAuth apps must approve it) |
| `gitlab` | `issuer` (default `https://gitlab.com`, or your GitLab URL), `clientId`, `clientSecret` — groups: GitLab groups | `openid`, `profile`, `email` — tick exactly these on the GitLab application |
| `google` | `clientId`, `clientSecret`, `allowedDomains` | `openid`, `profile`, `email` — Google sends no groups, so `allowedGroups` is refused |
| `oidc` | `issuer`, `clientId`, `clientSecret`, `scopes`, `usernameClaim`, `groupsClaim` | `openid`, `profile`, `email`, plus `groups` when discovery offers it; `scopes` replaces the list (`openid` is always added) |
| `ldap` | `url`, `startTLS`, `bindDN`, `bindPassword`, `userBaseDN`, `userFilter` (default `(uid={username})`; AD: `(sAMAccountName={username})`), `groupBaseDN`, `groupFilter` (default `(member={dn})`), attribute names | — |

A scope the app or client at the provider doesn't allow stops sign-in with `invalid_scope`; *Test* in Roam (`POST /api/v1/providers/{id}/test`) lists the scopes Gate asks for and warns about configured ones the provider doesn't offer.

Every provider also accepts `allowedDomains` (email domains) and `allowedGroups`. Secrets are encrypted at rest and never returned by the API.

## Bindings

```json
{ "subjectKind": "group", "subject": "github:acme/platform", "role": "admin",
  "scope": "namespaces", "namespaces": ["staging", "prod"], "note": "Platform team" }
```

| `subjectKind` | `subject` |
| ------------- | --------- |
| `user` | a Gate user ID, e.g. `alice@acme.com` |
| `group` | a Gate group, e.g. `github:acme/platform` |
| `aws` | an IAM role or user ARN (EKS with `aws-auth`) — people keep using `aws eks get-token` |
| `k8s-user`, `k8s-group` | a raw Kubernetes name, used as-is — Google accounts/groups on GKE, Entra ID object IDs on AKS |

`role` is any ClusterRole (`view`, `edit`, `admin`, `cluster-admin` or your own); `scope` is `cluster` or `namespaces`. Note that `admin`, even with `scope: cluster`, is Kubernetes' *namespace* admin: it can't list nodes, CRDs, PersistentVolumes or StorageClasses. Grant `cluster-admin` to someone who administers the cluster.

`user` subjects are stored the way sessions carry them — lowercase, without the `roam:` prefix (`Alice@Acme.com` and `roam:alice@acme.com` both become `alice@acme.com`), so a binding always matches the person Gate impersonates.

On EKS clusters that use access entries instead of `aws-auth`, Roam adds the access entry with your AWS credentials; Gate still manages the RBAC side.

## Signing in from apps and the CLI

Apps sign in through the browser and get the token back on their own computer (RFC 8252 loopback):

```sh
# 1. The app listens on a loopback port and starts a request with that address.
curl -X POST https://gate.example.com/api/v1/login-requests -d '{"returnURL":"http://127.0.0.1:53682/callback"}'
# → {"id": "…", "pollSecret": "…", "url": "https://gate.example.com/login?req=…"}
# 2. It opens url in the browser. After sign-in the browser comes back to
#    http://127.0.0.1:53682/callback?req=…&code=…
# 3. It collects the token with its poll secret and that one-time code:
curl -X POST https://gate.example.com/api/v1/login-requests/<id>/collect -d '{"pollSecret":"…","code":"…"}'
# → {"state": "done", "token": "rg_…"}   (state is "pending", "failed" or "expired" otherwise)
```

The code only ever reaches the computer where the person signs in, so sending someone a sign-in link can't hand their session to whoever started the request.

Or open `https://<gate>/login` in a browser. After signing in, *Open in Roam* hands the session to the Roam app on the computer or phone (`roam://gate/signin`, a one-time code that works for 10 minutes): Roam adds the cluster — asking first for a Gate it doesn't know yet — or signs in to it again. A browser that opened Roam once opens it by itself after later sign-ins. The page always offers the kubeconfig download too. When Gate's certificate isn't publicly trusted, the link carries the SHA-256 of its CA and Roam pins `GET /ca.crt` against it. On the phone, Roam only signs in (Add Cluster → Roam Gate, or the sign-in button by a Gate cluster in Settings); access control and the audit trail stay in the desktop app.

## API

All endpoints take `Authorization: Bearer <token>` (or `X-Roam-Gate-Token: <token>` — the Kubernetes API server's service proxy drops `Authorization`); admin endpoints need an admin session or the bootstrap token.

| | |
| - | - |
| `GET /api/v1/info` | Cluster name, providers (public) |
| `GET /api/v1/me` · `POST /api/v1/logout` · `GET /api/v1/kubeconfig` | The signed-in person |
| `GET/POST /api/v1/providers` · `PUT/DELETE /api/v1/providers/{id}` · `POST …/{id}/test` | Sign-in providers |
| `GET /api/v1/users` · `PATCH /api/v1/users/{id}` (`{"disabled":true}`) · `GET /api/v1/groups` | People who signed in |
| `GET/POST /api/v1/bindings` · `PUT/DELETE /api/v1/bindings/{id}` | Permissions |
| `GET /api/v1/sessions` · `DELETE /api/v1/sessions/{id}` | Active sessions |
| `GET /api/v1/audit?user=&kind=&verb=&namespace=&resource=&q=&denied=true&since=&until=&before=&limit=` | Audit trail |
| `GET /api/v1/cluster/roles` · `GET /api/v1/cluster/namespaces` · `GET /api/v1/status` | Cluster info, reconcile status |

Errors are `{"error": "<message>", "code": "<stable code>"}`. Messages — API errors, binding statuses and the sign-in pages — follow `Accept-Language` (English and Vietnamese so far; see `internal/msg` to add one).

Deleting or turning off a sign-in method ends the sessions it started. Disabling a user ends theirs.

Audit events are also written to stdout as JSON lines (`{"audit": …}`), so your log pipeline can keep them longer.

## Development

```sh
go test ./...
GATE_KUBECONFIG=~/.kube/config GATE_EXTERNAL_URL=http://localhost:8443 GATE_DATA_DIR=./data \
GATE_SECRET_KEY=$(head -c32 /dev/urandom | base64) GATE_ADMIN_TOKEN=dev go run ./cmd/roam-gate
```

## License

Apache-2.0
