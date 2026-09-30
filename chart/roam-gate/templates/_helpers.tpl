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
