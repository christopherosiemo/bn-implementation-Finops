package provider

import "github.com/christopherosiemo/bn-implementation-Finops/internal/model"

// Reviewed, versioned documentation excerpt: these two EBS-optimized rows have
// sustained fixed performance (EC2 footnote 2), not a burst-credit allowance.
// This supplies only an instance I/O cap. Native orderability, provisioned
// storage, CPU/memory/processor, metrics and customer economics remain separate.
// The hash covers this exact excerpt asset, never a claimed full HTTP response.
const rdsDocumentedIOAssetSHA256 = "140536ab0a2f42f364dfc63d8245fd4cbf27e34c63bcbe5b946849a49a2db53f"

const rdsDocumentedIOAssetV1 = `{
  "schema_version": "1",
  "source_revision": "2026-10-20",
  "basis": "AWS_DOCUMENTED_NON_BURST_BASELINE_V1",
  "provenance": "SELECTED_AWS_WEB_DOCUMENTATION_TABLE_COLUMNS_AND_FOOTNOTE_NOT_FULL_HTTP_BODY",
  "sources": [
    {
      "url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.DBInstanceClass.Summary.html",
      "raw_excerpt": "db.r6i.12xlarge | EBS-optimized only | 15,000 Mbps\ndb.r6i.8xlarge | EBS-optimized only | 10,000 Mbps\nBoth rows are unstarred; the RDS hardware terminology links instance IOPS to underlying EC2 EBS-optimized specifications.",
      "raw_excerpt_sha256": "fd40add84a60093b283528f161a312ce95068003d5acf4a426b5be17ccfee309"
    },
    {
      "url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-optimized.html",
      "raw_excerpt": "Instance type | EBS bandwidth (Mbps) | Throughput (MB/s, 128 KiB I/O) | IOPS (16 KiB I/O)\nr6i.8xlarge [2] | 10000 | 1250.0 | 40000\nr6i.12xlarge [2] | 15000 | 1875.0 | 60000\n[2] These instances can sustain their stated performance indefinitely.",
      "raw_excerpt_sha256": "12b9844a401714befa47857ecc69ef8975e498dab7883ee70a5c4611913531eb"
    }
  ],
  "entries": [
    {
      "class_id": "db.r6i.8xlarge",
      "iops": "40000",
      "throughput_bytes_per_second": "1250000000"
    },
    {
      "class_id": "db.r6i.12xlarge",
      "iops": "60000",
      "throughput_bytes_per_second": "1875000000"
    }
  ]
}
`

// RDSDocumentedIOBaselineAsset returns isolated exact bytes for immutable archival.
func RDSDocumentedIOBaselineAsset() []byte { return []byte(rdsDocumentedIOAssetV1) }

// RDSDocumentedIOBaseline admits only the literal reviewed non-burst rows.
// Unknown and burst-dependent classes have no baseline; provisioned settings
// and orderable maxima never fill this missing physical-capacity evidence.
func RDSDocumentedIOBaseline(class string) (model.Document, error) {
	return rdsDocumentedIOBaseline(RDSDocumentedIOBaselineAsset(), class)
}

func rdsDocumentedIOBaseline(raw []byte, class string) (model.Document, error) {
	if rdsSHA(raw) != rdsDocumentedIOAssetSHA256 {
		return nil, ErrRDSRead
	}
	var asset struct {
		Schema     string `json:"schema_version"`
		Revision   string `json:"source_revision"`
		Basis      string `json:"basis"`
		Provenance string `json:"provenance"`
		Sources    []struct {
			URL    string `json:"url"`
			Raw    string `json:"raw_excerpt"`
			SHA256 string `json:"raw_excerpt_sha256"`
		} `json:"sources"`
		Entries []struct {
			Class      string `json:"class_id"`
			IOPS       string `json:"iops"`
			Throughput string `json:"throughput_bytes_per_second"`
		} `json:"entries"`
	}
	if rdsJSON(raw, &asset) != nil || asset.Schema != "1" || asset.Revision != "2026-10-20" || asset.Basis != "AWS_DOCUMENTED_NON_BURST_BASELINE_V1" || len(asset.Sources) != 2 || len(asset.Entries) != 2 {
		return nil, ErrRDSRead
	}
	urls := []string{}
	for _, source := range asset.Sources {
		if rdsSHA([]byte(source.Raw)) != source.SHA256 {
			return nil, ErrRDSRead
		}
		urls = append(urls, source.URL)
	}
	for _, row := range asset.Entries {
		if row.Class == class {
			return model.Document{"iops": row.IOPS, "throughput_bytes_per_second": row.Throughput, "basis": asset.Basis, "class_id": row.Class, "source_excerpt_sha256": rdsDocumentedIOAssetSHA256, "source_urls": urls, "source_revision": asset.Revision}, nil
		}
	}
	return nil, nil
}
