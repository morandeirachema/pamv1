{{- define "pamv1.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "pamv1.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
guacd resource name and selector-label value. Both re-truncate to 63 chars after
appending "-guacd" because pamv1.fullname / pamv1.name are already truncated to 63,
so a long release name would otherwise overflow the Kubernetes name (RFC-1035) and
label-value limits. Use guacdFullname for metadata.name / PAM_GUACD_ADDR host and
guacdName for the app.kubernetes.io/name label value; both must agree so the
Service and NetworkPolicy podSelectors match the pod.
*/}}
{{- define "pamv1.guacdFullname" -}}
{{- printf "%s-guacd" (include "pamv1.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "pamv1.guacdName" -}}
{{- printf "%s-guacd" (include "pamv1.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "pamv1.labels" -}}
app.kubernetes.io/name: {{ include "pamv1.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "pamv1.selectorLabels" -}}
app.kubernetes.io/name: {{ include "pamv1.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "pamv1.secretName" -}}
{{- if .Values.secret.existingSecret -}}
{{- .Values.secret.existingSecret -}}
{{- else if .Values.secret.create -}}
{{- printf "%s-secrets" (include "pamv1.fullname" .) -}}
{{- else -}}
{{- fail "Provide credentials: set secret.existingSecret to a pre-created Secret, or secret.create=true with secret.data. create is false by default so PAM_MASTER_KEY does not land in Helm release history." -}}
{{- end -}}
{{- end -}}
