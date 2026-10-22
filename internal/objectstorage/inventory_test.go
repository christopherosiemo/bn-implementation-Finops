package objectstorage

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"
)

type inventoryMemory struct {
	objects        map[string][]byte
	archive        map[string][]byte
	checkpoints    map[string]model.Document
	rows           map[string]InventoryRow
	opens          map[string]int
	writes         int
	boundaryCalls  int
	changed        bool
	corruptArchive bool
}

func (m *inventoryMemory) OpenObject(_ context.Context, r Registration, key, version string) (Object, error) {
	raw, ok := m.objects[key]
	if !ok {
		return Object{}, errors.New("not found")
	}
	if version != "" && version != "native-version" {
		return Object{}, errors.New("version mismatch")
	}
	m.opens[key]++
	return Object{Bucket: r.ReportBucket, Key: key, VersionID: "native-version", Length: int64(len(raw)), Body: io.NopCloser(bytes.NewReader(raw))}, nil
}
func (m *inventoryMemory) ReportBoundary(_ context.Context, r Registration) (model.Document, error) {
	m.boundaryCalls++
	policy := "policy"
	if m.changed && m.boundaryCalls > 1 {
		policy = "changed"
	}
	return model.Document{"configuration": model.Document{"IncludedObjectVersions": "All"}, "configuration_hash": "configuration", "writer_policy_hash": policy}, nil
}
func (m *inventoryMemory) Archive(_ context.Context, tenant, kind, id string, raw []byte) (model.Document, error) {
	key := "tenant/" + tenant + "/native/" + id + "/" + kind + "/" + BytesHash(raw)
	m.archive[key] = append([]byte{}, raw...)
	return model.Document{"bucket": "raw", "key": key, "version_id": "immutable-version", "body_sha256": BytesHash(raw)}, nil
}
func (m *inventoryMemory) Read(_ context.Context, tenant string, ref model.Document) ([]byte, error) {
	if !strings.HasPrefix(model.String(ref, "key"), "tenant/"+tenant+"/") {
		return nil, errors.New("foreign tenant")
	}
	if m.corruptArchive {
		return []byte("altered"), nil
	}
	return m.archive[model.String(ref, "key")], nil
}
func (m *inventoryMemory) WriteObjectRows(_ context.Context, _ Scope, generation, batch string, rows []InventoryRow) (model.Document, error) {
	m.writes++
	for _, row := range rows {
		m.rows[generation+":"+row.ID] = row
	}
	return model.Document{"row_count": len(rows), "canonical_hash": Hash(rows), "batch_id": batch}, nil
}
func (m *inventoryMemory) ValidateObjectGeneration(_ context.Context, _ Scope, generation string, n int64) error {
	count := int64(0)
	seen := map[string]bool{}
	for id, row := range m.rows {
		if !strings.HasPrefix(id, generation+":") {
			continue
		}
		if seen[row.ObjectIdentity] {
			return errors.New("duplicate object")
		}
		seen[row.ObjectIdentity] = true
		count++
	}
	if count != n {
		return errors.New("count mismatch")
	}
	return nil
}
func inventoryFixture(t *testing.T) (*InventoryPipeline, Registration, *inventoryMemory, string) {
	t.Helper()
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	r := Registration{ID: "s3-source", TenantID: "tenant-s3", Kind: InventoryKind, AccountID: "111122223333", Region: "eu-west-1", ReadRoleBindingID: "read", Bucket: "data-bucket", ReportBucket: "report-bucket", ReportOwner: "111122223333", Prefix: "reports/", InventoryID: "native-config", Version: 1, Enabled: true, Datasets: []DatasetSelector{{ID: "logs", Kind: "PREFIX", Prefix: "logs/", DatasetVersion: 1, DatasetHash: strings.Repeat("a", 64)}}}
	m := &inventoryMemory{objects: map[string][]byte{}, archive: map[string][]byte{}, checkpoints: map[string]model.Document{}, rows: map[string]InventoryRow{}, opens: map[string]int{}}
	csv := "data-bucket,logs/a%20b,v1,true,false,1024,2026-01-01T00:00:00Z,STANDARD\n" + "data-bucket,logs/a%20b,v0,false,false,1048576,2025-01-01T00:00:00Z,STANDARD\n"
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	_, _ = io.WriteString(gz, csv)
	_ = gz.Close()
	file := "reports/data-bucket/native-config/data/part.csv.gz"
	sum := md5.Sum(compressed.Bytes())
	manifest := InventoryManifest{SourceBucket: r.Bucket, DestinationBucket: "arn:aws:s3:::" + r.ReportBucket, Version: "2016-11-30", CreationTimestamp: strconv.FormatInt(now.UnixMilli(), 10), FileFormat: "CSV", FileSchema: "Bucket, Key, VersionId, IsLatest, IsDeleteMarker, Size, LastModifiedDate, StorageClass", Files: []InventoryFile{{Key: file, Size: int64(compressed.Len()), MD5: hex.EncodeToString(sum[:])}}}
	raw, _ := json.Marshal(manifest)
	key := "reports/data-bucket/native-config/2026-10-20T00-00Z/manifest.json"
	md := md5.Sum(raw)
	m.objects[key] = raw
	m.objects[strings.TrimSuffix(key, "manifest.json")+"manifest.checksum"] = []byte(hex.EncodeToString(md[:]))
	m.objects[file] = compressed.Bytes()
	p := &InventoryPipeline{Reader: m, Archive: m, Facts: m, IdentityKey: bytes.Repeat([]byte{0x12}, 32), IdentityKeyVersion: "synthetic-v1", Now: func() time.Time { return now }, LoadCheckpoint: func(_ context.Context, key string) (model.Document, error) { return m.checkpoints[key], nil }, SaveCheckpoint: func(_ context.Context, key string, d model.Document) error { m.checkpoints[key] = d; return nil }}
	return p, r, m, key
}
func TestS3InventoryNativePopulationAndResumableImmutableEvidence(t *testing.T) {
	p, r, m, key := inventoryFixture(t)
	g, e := p.Ingest(context.Background(), r, key)
	if e != nil {
		t.Fatal(e)
	}
	if !g.Complete || len(g.Cohorts) != 2 || model.String(g.Inventory, "row_count") != "2" || model.String(g.Inventory, "identity_key_version") != "synthetic-v1" {
		t.Fatalf("invalid population %#v", g.Inventory)
	}
	for _, c := range g.Cohorts {
		if model.String(c, "dataset_id") != "logs" || model.Number(c, "dataset_version") != 1 || model.String(c, "object_count") != "1" || len(model.String(c, "population_hash")) != 64 || model.String(Doc(c["access"]), "state") != "ACCESS_UNKNOWN" {
			t.Fatalf("cohort %#v", c)
		}
	}
	for _, row := range m.rows {
		if row.Fields["Key"] != "" || len(row.ObjectIdentity) != 64 {
			t.Fatal("raw key escaped restricted archive")
		}
	}
	writes := m.writes
	again, e := p.Ingest(context.Background(), r, key)
	if e != nil || again.SourceVersion != g.SourceVersion || m.writes != writes {
		t.Fatalf("replay duplicated analytics: %v", e)
	}
	p.IdentityKeyVersion = "synthetic-v2"
	rotated, e := p.Ingest(context.Background(), r, key)
	if e != nil || rotated.SourceVersion == g.SourceVersion {
		t.Fatal("identity rotation mixed generations", e)
	}
}
func TestS3InventoryPartialAlteredWrongScopeAndArchiveFailClosed(t *testing.T) {
	for _, name := range []string{"missing-file", "wrong-account", "wrong-region", "writer-changed", "altered-file", "archive-altered", "missing-key", "foreign-tenant"} {
		t.Run(name, func(t *testing.T) {
			p, r, m, key := inventoryFixture(t)
			switch name {
			case "missing-file":
				delete(m.objects, "reports/data-bucket/native-config/data/part.csv.gz")
			case "wrong-account":
				r.AccountID = "wrong"
			case "wrong-region":
				r.Region = "moon-1"
			case "writer-changed":
				m.changed = true
			case "altered-file":
				m.objects["reports/data-bucket/native-config/data/part.csv.gz"][12] ^= 1
			case "archive-altered":
				m.corruptArchive = true
			case "missing-key":
				p.IdentityKey = nil
			case "foreign-tenant":
				r.TenantID = "../tenant"
			}
			g, e := p.Ingest(context.Background(), r, key)
			if e == nil || g.Complete {
				t.Fatal("invalid evidence became complete")
			}
		})
	}
}
func TestS3InventoryTenantKeyedIdentitiesAndExactSmallObjectBands(t *testing.T) {
	fields := map[string]string{"Bucket": "data-bucket", "Key": "logs/secret-customer-name", "VersionId": "v1", "Size": "131071", "StorageClass": "STANDARD", "LastModifiedDate": "2026-01-01T00:00:00Z", "IsLatest": "true", "IsDeleteMarker": "false"}
	p, r, _, _ := inventoryFixture(t)
	at := p.now()
	row, c, e := parseInventoryRow(r, "generation", "part", 0, fields, at, true, p.IdentityKey)
	if e != nil {
		t.Fatal(e)
	}
	r.TenantID = "other"
	other, _, e := parseInventoryRow(r, "generation", "part", 0, fields, at, true, p.IdentityKey)
	if e != nil || row.ObjectIdentity == other.ObjectIdentity {
		t.Fatal("tenant key derivation missing")
	}
	if c.SizeBands[3].TotalBytes != 131071 {
		t.Fatal("below128KiB was rounded")
	}
	fields["Size"] = "131072"
	_, above, e := parseInventoryRow(r, "generation", "part", 0, fields, at, true, p.IdentityKey)
	if e != nil || above.SizeBands[4].Count != 1 {
		t.Fatal("128KiB minimum billing partition differs")
	}
}
func TestS3ReportWriterAndConfigurationAuthority(t *testing.T) {
	_, r, _, _ := inventoryFixture(t)
	policy := model.Document{"Statement": []model.Document{{"Effect": "Allow", "Principal": model.Document{"Service": "s3.amazonaws.com"}, "Action": "s3:PutObject", "Resource": "arn:aws:s3:::report-bucket/reports/*", "Condition": model.Document{"StringEquals": model.Document{"aws:SourceAccount": r.AccountID, "aws:SourceArn": "arn:aws:s3:::data-bucket"}}}}}
 statementsValid:=Rows(policy["Statement"]);for k,v:=range map[string]string{"aws:PrincipalServiceName":"s3.amazonaws.com","aws:SourceArn":"arn:aws:s3:::data-bucket","aws:SourceAccount":r.AccountID}{statementsValid=append(statementsValid,model.Document{"Effect":"Deny","Principal":"*","Action":[]string{"s3:PutObject","s3:DeleteObject","s3:DeleteObjectVersion"},"Resource":"arn:aws:s3:::report-bucket/reports/*","Condition":model.Document{"StringNotEqualsIfExists":model.Document{k:v}}})};policy["Statement"]=statementsValid
	if e := ValidateReportWriterPolicy(r, policy); e != nil {
		t.Fatal(e)
	}
	bad := Doc(policy)
	statements := Rows(bad["Statement"])
	statements = append(statements, model.Document{"Effect": "Allow", "Principal": "*", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::report-bucket/*"})
	bad["Statement"] = statements
	if ValidateReportWriterPolicy(r, bad) == nil {
		t.Fatal("arbitrary writer accepted")
	}
	c := model.Document{"Id": r.InventoryID, "IsEnabled": true, "IncludedObjectVersions": "All", "Destination": model.Document{"S3BucketDestination": model.Document{"Bucket": "arn:aws:s3:::report-bucket", "Prefix": "reports", "Format": "CSV", "AccountId": r.ReportOwner}}}
	if e := ValidateReportConfiguration(r, c); e != nil {
		t.Fatal(e)
	}
	Doc(Doc(c["Destination"])["S3BucketDestination"])["Format"] = "Parquet"
	c["Destination"] = model.Document{"S3BucketDestination": model.Document{"Bucket": "arn:aws:s3:::report-bucket", "Prefix": "reports", "Format": "Parquet"}}
	if ValidateReportConfiguration(r, c) == nil {
		t.Fatal("unsupported population format became trusted")
	}
}
