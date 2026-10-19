package fleethistory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

func digest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func clone[T any](v T) T                       { b, _ := json.Marshal(v); var out T; _ = json.Unmarshal(b, &out); return out }
func RegistrationHash(r Registration) string   { return digest(r) }
func DefinitionHash(d DemandDefinition) string { return digest(d) }
func normalizeRef(r *SourceRef)                { r.CapturedAt = r.CapturedAt.UTC() }
func normalizeObservation(o *MembershipObservation) {
	o.ObservedAt = o.ObservedAt.UTC()
	o.ReceivedAt = o.ReceivedAt.UTC()
	normalizeRef(&o.Source)
	for i := range o.Members {
		if o.Members[i].LaunchTime != nil {
			v := o.Members[i].LaunchTime.UTC()
			o.Members[i].LaunchTime = &v
		}
		if o.Members[i].Hardware != nil {
			normalizeRef(o.Members[i].Hardware)
		}
	}
	sort.Slice(o.Members, func(i, j int) bool { return o.Members[i].InstanceID < o.Members[j].InstanceID })
}
func normalizeSample(s *DemandSample) {
	s.Start = s.Start.UTC()
	s.Time = s.Time.UTC()
	if s.Epoch != nil {
		v := s.Epoch.UTC()
		s.Epoch = &v
	}
	s.ReceivedAt = s.ReceivedAt.UTC()
	normalizeRef(&s.Source)
}
func ObservationHash(o MembershipObservation) string {
	o = clone(o)
	normalizeObservation(&o)
	return digest(o)
}
func SampleHash(s DemandSample) string { s = clone(s); normalizeSample(&s); return digest(s) }
func normalizedInput(in Input) Input {
	in = clone(in)
	in.Start = in.Start.UTC()
	in.End = in.End.UTC()
	in.AsOf = in.AsOf.UTC()
	for i := range in.Sources {
		in.Sources[i].CheckedAt = in.Sources[i].CheckedAt.UTC()
	}
	for i := range in.Observations {
		normalizeObservation(&in.Observations[i])
	}
	for i := range in.Demand {
		normalizeSample(&in.Demand[i])
	}
	sort.Slice(in.Sources, func(i, j int) bool {
		a, b := in.Sources[i], in.Sources[j]
		if a.SourceID != b.SourceID {
			return a.SourceID < b.SourceID
		}
		return digest(a) < digest(b)
	})
	sort.Slice(in.Observations, func(i, j int) bool {
		a, b := in.Observations[i], in.Observations[j]
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return ObservationHash(a) < ObservationHash(b)
	})
	sort.Slice(in.Demand, func(i, j int) bool {
		a, b := in.Demand[i], in.Demand[j]
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return SampleHash(a) < SampleHash(b)
	})
	return in
}
func InputHash(in Input) string { return digest(normalizedInput(in)) }

// SnapshotHash excludes only the generated hash itself. InputHash includes all
// supplied records, even blocked/conflicting/superseded ones and source states.
// Replays keep original receipt times; a fresh collection is a different input.
func SnapshotHash(a Analysis) string { a.Hash = ""; return digest(a) }

// ValidateSnapshot proves equality to this exact resolved input. It does not
// prove that an old input is still current; integration must reload source and
// registration states before capturing or using a new read-only analysis.
func ValidateSnapshot(a Analysis, in Input) error {
	if !hashPattern.MatchString(a.Hash) || SnapshotHash(a) != a.Hash {
		return invalid("HISTORY_SNAPSHOT_HASH_INVALID")
	}
	expected, err := Analyze(in)
	if err != nil {
		return err
	}
	if a.Hash != expected.Hash {
		return invalid("HISTORY_SNAPSHOT_BINDING_CHANGED")
	}
	return nil
}
