package service

import (
	"bytes"
	"encoding/json"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

// Native configuration clocks and metric quantities can be fractional. Keep
// their decimal JSON representation while projecting immutable EBS evidence.
func storageObject(value any) model.Document {
	raw, _ := json.Marshal(value)
	out := model.Document{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	_ = decoder.Decode(&out)
	return out
}
func storageRows(value any) []model.Document {
	raw, _ := json.Marshal(value)
	out := []model.Document{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	_ = decoder.Decode(&out)
	return out
}
