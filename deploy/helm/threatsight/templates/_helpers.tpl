{{- define "threatsight.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "threatsight.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "threatsight.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "threatsight.labels" -}}
app.kubernetes.io/name: {{ include "threatsight.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
threatsight.io/profile: {{ .Values.global.deploymentProfile | quote }}
{{- end -}}

{{- define "threatsight.selectorLabels" -}}
app.kubernetes.io/name: {{ include "threatsight.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "threatsight.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "threatsight.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "threatsight.image" -}}
{{- $repo := index . 0 -}}
{{- $tag := index . 1 -}}
{{- $digest := index . 2 -}}
{{- if $digest -}}
{{ printf "%s@%s" $repo $digest }}
{{- else -}}
{{ printf "%s:%s" $repo $tag }}
{{- end -}}
{{- end -}}

{{- define "threatsight.configChecksum" -}}
{{ include (print $.Template.BasePath "/configmap.yaml") . | sha256sum }}
{{- end -}}
