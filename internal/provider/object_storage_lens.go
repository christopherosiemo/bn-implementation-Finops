package provider

import (
	"context"
	"encoding/xml"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/objectstorage"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type objectXML struct {
	XMLName xml.Name
	Text    string      `xml:",chardata"`
	Nodes   []objectXML `xml:",any"`
}

func objectXMLDocument(x objectXML) any {
	if len(x.Nodes) == 0 {
		if x.XMLName.Local == "IsEnabled" {
			b, e := strconv.ParseBool(strings.TrimSpace(x.Text))
			if e == nil {
				return b
			}
		}
		return strings.TrimSpace(x.Text)
	}
	d := model.Document{}
	for _, n := range x.Nodes {
		v := objectXMLDocument(n)
		if prior, exists := d[n.XMLName.Local]; exists {
			if list, ok := prior.([]any); ok {
				d[n.XMLName.Local] = append(list, v)
			} else {
				d[n.XMLName.Local] = []any{prior, v}
			}
		} else {
			d[n.XMLName.Local] = v
		}
	}
	return d
}

// S3StorageLensConfiguration is read-only and bound to one registered account,
// configuration and commercial AWS region. No S3Control mutation is exposed.
func (a *AWS) S3StorageLensConfiguration(ctx context.Context, r objectstorage.Registration) (model.Document, error) {
	region := r.ReportRegion
	if region == "" {
		region = r.Region
	}
	scope := objectstorage.Scope{TenantID: r.TenantID, AccountID: r.AccountID, Region: region}
	cfg, capture, e := objectSDK(a, scope)
	if e != nil {
		return nil, e
	}
	if e = objectIdentity(ctx, cfg, scope); e != nil {
		return nil, e
	}
	if strings.ContainsAny(r.InventoryID, "/\\?#") || r.InventoryID == "" {
		return nil, errors.New("S3_LENS_ID_INVALID")
	}
	req, e := http.NewRequestWithContext(objectContext(ctx, "GetStorageLensConfiguration"), http.MethodGet, "https://"+r.AccountID+".s3-control."+region+".amazonaws.com/v20180820/storagelens/"+r.InventoryID, nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("x-amz-account-id", r.AccountID)
	creds, e := cfg.Credentials.Retrieve(ctx)
	if e != nil {
		return nil, errors.New("S3_LENS_CREDENTIALS_UNAVAILABLE")
	}
	if e = v4.NewSigner().SignHTTP(ctx, creds, req, objectstorage.BytesHash(nil), "s3", region, time.Now().UTC()); e != nil {
		return nil, e
	}
	response, e := capture.Do(req)
	if e != nil {
		return nil, e
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, errors.New("S3_LENS_CONFIGURATION_UNAVAILABLE")
	}
	var tree objectXML
	if xml.NewDecoder(response.Body).Decode(&tree) != nil {
		return nil, errors.New("S3_LENS_CONFIGURATION_INVALID")
	}
	all := objectstorage.Doc(objectXMLDocument(tree))
	c := objectstorage.Doc(all["StorageLensConfiguration"])
	if model.String(c, "Id") != r.InventoryID || c["IsEnabled"] != true {
		return nil, errors.New("S3_LENS_CONFIGURATION_SCOPE_MISMATCH")
	}
	include, exclude := objectstorage.Doc(c["Include"]), objectstorage.Doc(c["Exclude"])
	bucketARN := "arn:aws:s3:::" + r.Bucket
	for _, x := range objectstorage.Values(objectstorage.Doc(exclude["Buckets"])["Arn"]) {
		if x == bucketARN {
			return nil, errors.New("S3_LENS_BUCKET_EXCLUDED")
		}
	}
	buckets := objectstorage.Values(objectstorage.Doc(include["Buckets"])["Arn"])
	if len(buckets) > 0 {
		found := false
		for _, x := range buckets {
			if x == bucketARN {
				found = true
			}
		}
		if !found {
			return nil, errors.New("S3_LENS_BUCKET_OUTSIDE_SCOPE")
		}
	}
	for _, x := range objectstorage.Values(objectstorage.Doc(exclude["Regions"])["Region"]) {
		if x == r.Region {
			return nil, errors.New("S3_LENS_REGION_EXCLUDED")
		}
	}
	regions := objectstorage.Values(objectstorage.Doc(include["Regions"])["Region"])
	if len(regions) > 0 {
		found := false
		for _, x := range regions {
			if x == r.Region {
				found = true
			}
		}
		if !found {
			return nil, errors.New("S3_LENS_REGION_OUTSIDE_SCOPE")
		}
	}
	c["native_frames"] = capture.frames
	return c, nil
}
