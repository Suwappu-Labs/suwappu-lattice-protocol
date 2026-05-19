{{/*
Common labels applied to every LTP-local resource in this chart.
Includes the kube-prometheus-stack release label so AlertManager and
Prometheus auto-discover our ServiceMonitors, PrometheusRules, and
AlertmanagerConfigs without operator overrides.
*/}}
{{- define "ltp-observability.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: observability
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
release: {{ .Release.Name }}
{{- end -}}
