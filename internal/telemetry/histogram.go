package telemetry

import (
	"encoding/json"
	"errors"
	"strconv"
)

// JSON represents populations as decimal strings; generic JSON/JS decoders must
// not round native uint64 values above 2^53.
func (h Histogram) MarshalJSON() ([]byte, error) {
	counts := []string{}
	for _, n := range h.BucketCounts {
		counts = append(counts, strconv.FormatUint(n, 10))
	}
	return json.Marshal(struct {
		Count        string   `json:"count"`
		Bounds       []string `json:"bounds"`
		BucketCounts []string `json:"bucket_counts"`
	}{strconv.FormatUint(h.Count, 10), h.Bounds, counts})
}
func (h *Histogram) UnmarshalJSON(raw []byte) error {
	var v struct {
		Count        string   `json:"count"`
		Bounds       []string `json:"bounds"`
		BucketCounts []string `json:"bucket_counts"`
	}
	if e := json.Unmarshal(raw, &v); e != nil {
		return e
	}
	count, e := strconv.ParseUint(v.Count, 10, 64)
	if e != nil {
		return e
	}
	h.Count, h.Bounds, h.BucketCounts = count, v.Bounds, []uint64{}
	for _, s := range v.BucketCounts {
		n, e := strconv.ParseUint(s, 10, 64)
		if e != nil {
			return e
		}
		h.BucketCounts = append(h.BucketCounts, n)
	}
	if !validHistogram(h) {
		return errors.New("TELEMETRY_HISTOGRAM_INVALID")
	}
	return nil
}
