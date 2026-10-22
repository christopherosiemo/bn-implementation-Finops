package fleethistory

import (
	"bytes"
	"encoding/json"
	"io"
)

// Strict decoding is for internal adapters too: unrecognized completeness,
// trusted flags, money or authority fields cannot acquire meaning by omission.
func decode(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > 4<<20 {
		return invalid("HISTORY_DOCUMENT_LIMIT")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return invalid("HISTORY_DOCUMENT_INVALID")
	}
	if d.Decode(new(any)) != io.EOF {
		return invalid("HISTORY_TRAILING_DOCUMENT")
	}
	return nil
}
func DecodeRegistration(raw []byte) (Registration, error) {
	var v Registration
	if err := decode(raw, &v); err != nil {
		return v, err
	}
	return v, ValidateRegistration(v)
}
func DecodeObservation(r Registration, raw []byte) (MembershipObservation, error) {
	var v MembershipObservation
	if err := decode(raw, &v); err != nil {
		return v, err
	}
	return v, ValidateObservation(r, v)
}
func DecodeDemandDefinition(r Registration, raw []byte) (DemandDefinition, error) {
	var v DemandDefinition
	if err := decode(raw, &v); err != nil {
		return v, err
	}
	return v, ValidateDemandDefinition(r, v)
}
func DecodeDemandSample(r Registration, d DemandDefinition, raw []byte) (DemandSample, error) {
	var v DemandSample
	if err := decode(raw, &v); err != nil {
		return v, err
	}
	return v, ValidateDemandSample(r, d, v)
}
