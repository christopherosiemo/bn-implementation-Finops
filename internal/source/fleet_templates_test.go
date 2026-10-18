package source

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func framedTemplateEvidence(now time.Time) provider.FleetTemplateEvidence {
	id := "lt-0123456789abcdef0"
	items := ""
	for _, v := range []uint64{1, 2} {
		kind := "m6i.4xlarge"
		if v == 2 {
			kind = "m6i.2xlarge"
		}
		items += fmt.Sprintf(`<item><launchTemplateId>%s</launchTemplateId><launchTemplateName>native-template</launchTemplateName><versionNumber>%d</versionNumber><launchTemplateData><instanceType>%s</instanceType><imageId>ami-0123456789abcdef0</imageId></launchTemplateData></item>`, id, v, kind)
	}
	body := []byte(`<DescribeLaunchTemplateVersionsResponse><launchTemplateVersionSet>` + items + `</launchTemplateVersionSet></DescribeLaunchTemplateVersionsResponse>`)
	values := url.Values{"Action": {"DescribeLaunchTemplateVersions"}, "Version": {"2016-11-15"}, "MaxResults": {"100"}, "ResolveAlias": {"false"}, "LaunchTemplateId": {id}, "LaunchTemplateVersion.1": {"1"}, "LaunchTemplateVersion.2": {"2"}}
	selector := values.Encode()
	var raw bytes.Buffer
	_ = binary.Write(&raw, binary.BigEndian, uint32(len(selector)))
	raw.WriteString(selector)
	_ = binary.Write(&raw, binary.BigEndian, uint64(len(body)))
	raw.Write(body)
	var decoded struct {
		Templates []provider.FleetTemplateVersion `xml:"launchTemplateVersionSet>item"`
	}
	_ = xml.Unmarshal(body, &decoded)
	return provider.FleetTemplateEvidence{SchemaVersion: "1", Provider: "AWS", Region: "eu-west-1", AccountID: "111122223333", CollectedAt: now, Raw: raw.Bytes(), RawSHA256: BytesHash(raw.Bytes()), Templates: decoded.Templates}
}
func TestFleetTemplateRawFactoryRequiresExactSelectorAndUnalteredNativeData(t *testing.T) {
	native := framedTemplateEvidence(time.Now().UTC())
	requests := []provider.FleetTemplateRequest{{ID: "lt-0123456789abcdef0", Version: 1}, {ID: "lt-0123456789abcdef0", Version: 2}}
	if _, e := fleetTemplateRaw(native, requests); e != nil {
		t.Fatal(e)
	}
	native.Templates[1].Data.InstanceType = "invented"
	if _, e := fleetTemplateRaw(native, requests); e == nil {
		t.Fatal("altered typed hardware accepted")
	}
	native = framedTemplateEvidence(time.Now().UTC())
	requests[1].Version = 3
	if _, e := fleetTemplateRaw(native, requests); e == nil {
		t.Fatal("different numbered template accepted")
	}
}

type fleetTemplateFixtureReader struct {
	fleetFixtureReader
	templates provider.FleetTemplateEvidence
}

func (r *fleetTemplateFixtureReader) FleetTemplateVersions(ctx context.Context, region, account string, requests []provider.FleetTemplateRequest) (provider.FleetTemplateEvidence, error) {
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 45*time.Second || region != r.templates.Region || account != r.templates.AccountID || len(requests) != 2 || requests[0].Version != 1 || requests[1].Version != 2 {
		return provider.FleetTemplateEvidence{}, errors.New("template request lost bound scope or deadline")
	}
	return r.templates, nil
}
func TestFleetTemplateFactoryArchivesBeforePublishingAndCannotProveStorageSafety(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL required")
	}
	ctx := context.Background()
	admin, e := store.Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Pool.Close()
	if e = admin.Migrate(ctx, "../../migrations"); e != nil {
		t.Fatal(e)
	}
	config, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	config.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, e := c.Exec(ctx, "SET ROLE finops_ingester")
		return e
	}
	pool, e := pgxpool.NewWithConfig(ctx, config)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	ingester := &store.Store{Pool: pool}
	for _, mode := range []string{"success", "missing-reader", "archive-failure", "revoke-during-archive"} {
		t.Run(mode, func(t *testing.T) {
			tenant := "fleet-lt-" + model.ID()
			parent := sourceFleetPlan(tenant)
			registration := FixtureRegistration(tenant, "source")
			now := time.Now().UTC()
			groups := framedFleetEvidence(parent, []provider.FleetGroup{nativeFleetGroup(parent, parent.Old, 20), nativeFleetGroup(parent, parent.Candidate, 0)}, now)
			templates := framedTemplateEvidence(now)
			if e := admin.Do(ctx, tenant, func(tx *store.Tx) error {
				if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
					return e
				}
				_, e := tx.SourceCreate(ctx, registration)
				return e
			}); e != nil {
				t.Fatal(e)
			}
			pipeline := FleetPipeline{Store: ingester, Now: func() time.Time { return now }, DiscoveryBindings: map[string]FleetDiscoveryBinding{"approved": {SourceID: "source", Binding: parent.Binding, OldASG: parent.Old.ID, CandidateASG: parent.Candidate.ID}}, ReaderFactory: func(context.Context, Registration, string) (FleetReader, error) {
				if mode == "missing-reader" {
					return &fleetFixtureReader{groups}, nil
				}
				return &fleetTemplateFixtureReader{fleetFixtureReader{groups}, templates}, nil
			}, Archive: func(_ context.Context, actualTenant, id string, raw []byte) (model.Document, error) {
				if actualTenant != tenant {
					return nil, errors.New("archive tenant mismatch")
				}
				if strings.HasPrefix(id, "templates-") {
					if !bytes.Equal(raw, templates.Raw) {
						return nil, errors.New("native LT bytes changed")
					}
					if e := ingester.Do(ctx, tenant, func(tx *store.Tx) error {
						rows, e := tx.SourceReceiptList(ctx, "AWS_FLEET_LAUNCH_TEMPLATES", "source")
						if e == nil && len(rows) != 0 {
							return errors.New("template receipt preceded archive")
						}
						return e
					}); e != nil {
						return nil, e
					}
					if mode == "archive-failure" {
						return nil, errors.New("fixture storage failure")
					}
					if mode == "revoke-during-archive" {
						if e := admin.Do(ctx, tenant, func(tx *store.Tx) error {
							if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
								return e
							}
							r, e := tx.SourceGet(ctx, "source")
							if e != nil {
								return e
							}
							r["enabled"] = false
							_, e = tx.SourceUpdate(ctx, "source", model.Number(r, "version"), r)
							return e
						}); e != nil {
							return nil, e
						}
					}
				}
				return model.Document{"bucket": "raw", "key": "tenant/" + tenant + "/fleet/" + id + "/raw.bin", "version_id": "v1", "body_sha256": BytesHash(raw)}, nil
			}}
			membership, e := pipeline.Discover(ctx, tenant, "approved")
			if e != nil {
				t.Fatal(e)
			}
			out, e := pipeline.CaptureTemplates(ctx, tenant, "source", model.String(membership, "id"))
			if mode == "success" {
				if e != nil || model.String(out, "kind") != "AWS_FLEET_LAUNCH_TEMPLATES" || model.String(out, "membership_receipt_id") != model.String(membership, "id") || model.String(out, "storage_status") != "UNKNOWN_REQUIRES_AMI_AND_ATTACHMENTS" || model.Bool(out, "execution_authorized") {
					t.Fatal("native hardware claimed storage/execution authority", e, out)
				}
			} else if e == nil {
				t.Fatal("incomplete template capture published")
			}
			if e := ingester.Do(ctx, tenant, func(tx *store.Tx) error {
				rows, e := tx.SourceReceiptList(ctx, "AWS_FLEET_LAUNCH_TEMPLATES", "source")
				if e != nil {
					return e
				}
				want := 0
				if mode == "success" {
					want = 1
				}
				if len(rows) != want {
					return fmt.Errorf("template receipt count %d != %d", len(rows), want)
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
		})
	}
}
