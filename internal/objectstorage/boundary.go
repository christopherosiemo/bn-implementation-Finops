package objectstorage

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"strings"
)

func Doc(v any) model.Document {
	b, _ := json.Marshal(v)
	d := model.Document{}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	_ = decoder.Decode(&d)
	return d
}
func Rows(v any) []model.Document {
	b, _ := json.Marshal(v)
	r := []model.Document{}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	_ = decoder.Decode(&r)
	return r
}
func Values(v any) []string {
	if s, ok := v.(string); ok {
		return []string{s}
	}
	b, _ := json.Marshal(v)
	out := []string{}
	_ = json.Unmarshal(b, &out)
	return out
}
func ValidateReportConfiguration(r Registration, c model.Document) error {
	if r.ReportType == "APP_ACCESS" {
		if r.ApprovedWriterPrincipal == "" || r.MetricDefinitionID == "" || r.MetricDefinitionVersion == "" || model.String(c, "approved_writer_principal_arn") != r.ApprovedWriterPrincipal || model.String(c, "metric_definition_id") != r.MetricDefinitionID || model.String(c, "metric_definition_version") != r.MetricDefinitionVersion {
			return errors.New("S3_APP_COLLECTOR_AUTHORITY_UNAVAILABLE")
		}
		return nil
	}
	if model.String(c, "Id") != r.InventoryID {
		return errors.New("S3_REPORT_CONFIGURATION_MISMATCH")
	}
	dest := Doc(Doc(c["Destination"])["S3BucketDestination"])
	if r.Kind == InventoryKind {
		if c["IsEnabled"] != true || model.String(c, "IncludedObjectVersions") == "" {
			return errors.New("S3_INVENTORY_CONFIGURATION_INCOMPLETE")
		}
	} else {
		if r.ReportType == "S3_STORAGE_LENS" {
			dest = Doc(Doc(c["DataExport"])["S3BucketDestination"])
			if c["IsEnabled"] != true || model.String(dest, "Arn") != "arn:aws:s3:::"+r.ReportBucket || model.String(dest, "AccountId") != r.ReportOwner || strings.TrimSuffix(model.String(dest, "Prefix"), "/") != strings.TrimSuffix(r.Prefix, "/") || model.String(dest, "Format") != "CSV" || model.String(dest, "OutputSchemaVersion") != "V_1" {
				return errors.New("S3_LENS_DESTINATION_OR_FORMAT_UNSUPPORTED")
			}
			return nil
		}
		dest = Doc(Doc(Doc(c["StorageClassAnalysis"])["DataExport"])["Destination"])
		dest = Doc(dest["S3BucketDestination"])
	}
	if model.String(dest, "Bucket") != "arn:aws:s3:::"+r.ReportBucket || strings.TrimSuffix(model.String(dest, "Prefix"), "/") != strings.TrimSuffix(r.Prefix, "/") || model.String(dest, "Format") != "CSV" {
		return errors.New("S3_REPORT_DESTINATION_OR_FORMAT_UNSUPPORTED")
	}
	if owner := model.String(dest, "AccountId"); owner != "" && owner != r.ReportOwner {
		return errors.New("S3_REPORT_OWNER_MISMATCH")
	}
	return nil
}
func ValidateReportWriterPolicy(r Registration, p model.Document) error {
	expected := "arn:aws:s3:::" + r.ReportBucket + "/" + r.Prefix + "*"
	found := false
	protected := map[string]bool{}
	service, sourceARN := "s3.amazonaws.com", "arn:aws:s3:::"+r.Bucket
	if r.ReportType == "S3_STORAGE_LENS" {
		region := r.ReportRegion
		if region == "" {
			region = r.Region
		}
		service = "storage-lens.s3.amazonaws.com"
		sourceARN = "arn:aws:s3:" + region + ":" + r.AccountID + ":storage-lens/" + r.InventoryID
	}
	required := map[string]string{"aws:PrincipalServiceName": service, "aws:SourceArn": sourceARN, "aws:SourceAccount": r.AccountID}
	if r.ReportType == "APP_ACCESS" {
		required = map[string]string{"aws:PrincipalArn": r.ApprovedWriterPrincipal}
	}
	for _, s := range Rows(p["Statement"]) {
		if model.String(s, "Effect") == "Deny" && s["Principal"] == "*" {
			exact := false
			for _, resource := range Values(s["Resource"]) {
				if resource == expected {
					exact = true
				}
			}
			actions := map[string]bool{}
			for _, action := range Values(s["Action"]) {
				actions[action] = true
			}
			condition := Doc(s["Condition"])
			notEqual := Doc(condition["StringNotEqualsIfExists"])
			if exact && actions["s3:PutObject"] && actions["s3:DeleteObject"] && actions["s3:DeleteObjectVersion"] && len(condition) == 1 && len(notEqual) == 1 {
				for k, want := range required {
					if want != "" && model.String(notEqual, k) == want {
						protected[k] = true
					}
				}
			}
		}
		if model.String(s, "Effect") != "Allow" {
			continue
		}
		if s["NotAction"] != nil || s["NotResource"] != nil {
			return errors.New("S3_REPORT_UNSUPPORTED_WRITE_PERMISSION")
		}
		write := false
		for _, a := range Values(s["Action"]) {
			if a == "*" || a == "s3:*" || strings.HasPrefix(a, "s3:Put") || strings.HasPrefix(a, "s3:Delete") || strings.ContainsAny(a, "*?") && !strings.HasPrefix(a, "s3:Get") && !strings.HasPrefix(a, "s3:List") {
				write = true
			}
		}
		if !write {
			continue
		}
		relevant := false
		for _, v := range Values(s["Resource"]) {
			if v == expected || v == "*" || v == "arn:aws:s3:::"+r.ReportBucket+"/*" || strings.HasPrefix(expected, strings.TrimSuffix(v, "*")) || strings.HasPrefix(v, strings.TrimSuffix(expected, "*")) {
				relevant = true
			}
		}
		if !relevant {
			continue
		}
		principal := Doc(s["Principal"])
		cond := Doc(s["Condition"])
		equal := Doc(cond["StringEquals"])
		arn := model.String(equal, "aws:SourceArn")
		if arn == "" {
			arn = model.String(Doc(cond["ArnLike"]), "aws:SourceArn")
		}
		approved := model.String(principal, "Service") == service && len(principal) == 1 && model.String(equal, "aws:SourceAccount") == r.AccountID && arn == sourceARN
		if r.ReportType == "APP_ACCESS" {
			approved = r.ApprovedWriterPrincipal != "" && len(principal) == 1 && model.String(principal, "AWS") == r.ApprovedWriterPrincipal
		}
		if !approved {
			return errors.New("S3_REPORT_UNAUTHORIZED_WRITER")
		}
		for _, a := range Values(s["Action"]) {
			if a != "s3:PutObject" {
				return errors.New("S3_REPORT_UNSUPPORTED_WRITE_PERMISSION")
			}
		}
		found = true
	}
	if !found {
		return errors.New("S3_REPORT_EXPECTED_WRITER_UNPROVEN")
	}
	for k := range required {
		if !protected[k] {
			return errors.New("S3_REPORT_EXCLUSIVE_WRITER_FENCE_REQUIRED")
		}
	}
	return nil
}
