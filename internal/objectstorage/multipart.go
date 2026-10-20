package objectstorage

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"math/big"
	"sort"
	"strconv"
	"time"
)

// MultipartCohorts preserves upload/part observations as review populations.
// They are not fabricated completed object identities or deletion authority.
func MultipartCohorts(b Bucket, observed time.Time, ref model.Document) []model.Document {
	observation := b.Configurations["multipart_uploads"]
	value := Doc(observation.Value)
	if observation.Status != "OBSERVED" || value["complete"] != true {
		return nil
	}
	groups := map[string][]model.Document{}
	for _, upload := range Rows(value["uploads"]) {
		class := model.String(upload, "storage_class")
		if class == "" {
			class = "UNKNOWN"
		}
		groups[class] = append(groups[class], upload)
	}
	classes := []string{}
	for class := range groups {
		classes = append(classes, class)
	}
	sort.Strings(classes)
	out := []model.Document{}
	for _, class := range classes {
		rows := groups[class]
		bytes := new(big.Int)
		minAge, maxAge := int64(0), int64(0)
		unknown := false
		bands := []model.Document{}
		sizes := make([]objectBand, 8)
		hashRows := []string{}
		for i, row := range rows {
			n, ok := new(big.Int).SetString(model.String(row, "size_bytes"), 10)
			if !ok || n.Sign() < 0 || !n.IsInt64() {
				unknown = true
				continue
			}
			bytes.Add(bytes, n)
			value := n.Int64()
			bounds := []int64{1024, 8192, 65536, 131072, 1048576, 16777216, 1073741824}
			band := 0
			for band < len(bounds) && value >= bounds[band] {
				band++
			}
			b := &sizes[band]
			if b.Count == 0 || value < b.MinBytes {
				b.MinBytes = value
			}
			if value > b.MaxBytes {
				b.MaxBytes = value
			}
			b.Count++
			b.TotalBytes += value
			at, e := time.Parse(time.RFC3339Nano, model.String(row, "initiated"))
			if e != nil {
				unknown = true
			} else {
				age := int64(observed.Sub(at) / (24 * time.Hour))
				if age < 0 {
					unknown = true
				}
				if i == 0 || age < minAge {
					minAge = age
				}
				if age > maxAge {
					maxAge = age
				}
			}
			hashRows = append(hashRows, Hash(row))
		}
		for _, b := range sizes {
			if b.Count > 0 {
				bands = append(bands, model.Document{"count": strconv.FormatInt(b.Count, 10), "total_bytes": strconv.FormatInt(b.TotalBytes, 10), "min_bytes": strconv.FormatInt(b.MinBytes, 10), "max_bytes": strconv.FormatInt(b.MaxBytes, 10)})
			}
		}
		sort.Strings(hashRows)
		cohort := model.Document{"id": "multipart-" + Hash(model.Document{"bucket": b.ARN, "class": class})[:24], "dataset_id": "bucket", "label": b.Name + " incomplete multipart uploads", "source_class": class, "access_tier": "", "state": "MULTIPART", "object_count": strconv.Itoa(len(rows)), "total_bytes": bytes.String(), "size_bands": bands, "age_days_min": strconv.FormatInt(minAge, 10), "age_days_max": strconv.FormatInt(maxAge, 10), "minimum_duration_remaining_days": nil, "inventory_complete": !unknown, "population_hash": Hash(hashRows), "source_ref": ref, "population_kind": "NATIVE_UPLOAD_PART_METADATA_NOT_COMPLETED_OBJECTS", "access": model.Document{"state": "ACCESS_UNKNOWN", "complete": false}, "execution_authorized": false}
		if unknown {
			cohort["age_days_min"] = nil
			cohort["age_days_max"] = nil
		}
		out = append(out, cohort)
	}
	return out
}
