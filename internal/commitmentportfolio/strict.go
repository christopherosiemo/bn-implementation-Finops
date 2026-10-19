package commitmentportfolio

import (
	"bytes"
	"encoding/json"
	"io"
)

func jsonValue(v any) ([]byte, error) { return json.Marshal(v) }
func decodeRecurringCharges(raw []byte) ([]RIRecurringCharge, error) {
	var out []RIRecurringCharge
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if e := decoder.Decode(&out); e != nil {
		return nil, e
	}
	if decoder.Decode(new(any)) != io.EOF || out == nil {
		return nil, ErrEvidence
	}
	return out, nil
}
