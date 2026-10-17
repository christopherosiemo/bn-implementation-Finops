{{- define "finops.image" -}}
{{- if .digest -}}{{ .repository }}@{{ .digest }}{{- else -}}{{ .repository }}:{{ .tag }}{{- end -}}
{{- end -}}
{{- define "finops.labels" -}}
app.kubernetes.io/part-of: finops
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "finops.temporal" -}}
{{- if .Values.temporal.enabled -}}finops-temporal:7233{{- else -}}{{ required "external.temporalAddress required with temporal disabled" .Values.external.temporalAddress }}{{- end -}}
{{- end -}}
{{- define "finops.clickhouse" -}}
{{- if .Values.clickhouse.enabled -}}http://finops-clickhouse:8123{{- else -}}{{ required "external.clickhouseUrl required with clickhouse disabled" .Values.external.clickhouseUrl }}{{- end -}}
{{- end -}}
