{{/*
Expand the name of the chart.
*/}}
{{- define "kaaval.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "kaaval.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "kaaval.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "kaaval.labels" -}}
helm.sh/chart: {{ include "kaaval.chart" . }}
{{ include "kaaval.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "kaaval.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kaaval.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Control-plane fullname
*/}}
{{- define "kaaval.controlPlane.fullname" -}}
{{- printf "%s-control-plane" (include "kaaval.fullname" .) }}
{{- end }}

{{/*
Control-plane labels
*/}}
{{- define "kaaval.controlPlane.labels" -}}
{{ include "kaaval.selectorLabels" . }}
app.kubernetes.io/component: control-plane
{{- end }}

{{/*
Control-plane selector labels
*/}}
{{- define "kaaval.controlPlane.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kaaval.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: control-plane
{{- end }}
