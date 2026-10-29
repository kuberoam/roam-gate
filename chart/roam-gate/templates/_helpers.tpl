{{- define "gate.name" -}}
{{- .Release.Name | trunc 50 | trimSuffix "-" -}}
{{- end -}}

{{- define "gate.selector" -}}
app.kubernetes.io/name: roam-gate
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "gate.labels" -}}
{{ include "gate.selector" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: roam
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
kuberoam.dev/component: roam-gate
{{- end -}}

{{- define "gate.externalURL" -}}
{{- if .Values.externalURL -}}
{{- .Values.externalURL | trimSuffix "/" -}}
{{- else if and .Values.ingress.enabled .Values.ingress.host -}}
https://{{ .Values.ingress.host }}
{{- else -}}
https://localhost:8443
{{- end -}}
{{- end -}}

{{- define "gate.scheme" -}}
{{- if eq .Values.tls.mode "none" }}HTTP{{ else }}HTTPS{{ end -}}
{{- end -}}

{{- define "gate.tlsSecret" -}}
{{- if eq .Values.tls.mode "secret" -}}
{{- required "tls.secretName is required with tls.mode=secret" .Values.tls.secretName -}}
{{- else -}}
{{ include "gate.name" . }}-tls
{{- end -}}
{{- end -}}

{{- /* The host people reach Gate at (from the Gate URL), without a port. */ -}}
{{- define "gate.externalHost" -}}
{{- regexReplaceAll ":[0-9]+$" (urlParse (include "gate.externalURL" .)).host "" -}}
{{- end -}}

{{- /* Fails unless cert-manager's API is there. */ -}}
{{- define "gate.requireCertManager" -}}
{{- if not (.Capabilities.APIVersions.Has "cert-manager.io/v1") -}}
{{- fail "cert-manager isn't installed in this cluster (no cert-manager.io/v1 API): install it, or pick another TLS option" -}}
{{- end -}}
{{- end -}}

{{- /* The Ingress's TLS Secret: tlsSecretName, or one cert-manager fills in. */ -}}
{{- define "gate.ingressTLSSecret" -}}
{{- .Values.ingress.tlsSecretName | default (ternary (printf "%s-ingress-tls" (include "gate.name" .)) "" (ne .Values.ingress.issuer.name "")) -}}
{{- end -}}
