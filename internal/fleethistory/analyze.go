package fleethistory

import (
	"math/big"
	"sort"
	"time"
)

type lineage struct {
	id, corrects, key, hash string
	received                time.Time
}

// resolve rejects forks/cycles instead of treating append order or lexical IDs
// as source recency. Corrections must address an existing immutable logical point.
// An inactive new head must not revive a superseded predecessor.
func resolve(records []lineage) (map[string]bool, []string, []Issue) {
	all := map[string]lineage{}
	bad := map[string]bool{}
	children := map[string][]string{}
	issues := []Issue{}
	mark := func(id, code string) { bad[id] = true; issues = append(issues, Issue{id, code}) }
	for _, r := range records {
		if old, ok := all[r.id]; ok {
			if old.hash != r.hash {
				mark(r.id, "HISTORY_IMMUTABLE_RECORD_CONFLICT")
			}
			continue
		}
		all[r.id] = r
	}
	for _, r := range all {
		if r.corrects == "" {
			continue
		}
		old, ok := all[r.corrects]
		if !ok {
			mark(r.id, "HISTORY_CORRECTION_TARGET_MISSING")
			continue
		}
		children[old.id] = append(children[old.id], r.id)
		if r.key != old.key || r.received.Before(old.received) {
			mark(r.id, "HISTORY_CORRECTION_BINDING_INVALID")
			mark(old.id, "HISTORY_CORRECTION_BINDING_INVALID")
		}
	}
	for id, child := range children {
		if len(child) > 1 {
			mark(id, "HISTORY_CORRECTION_BRANCH_CONFLICT")
			for _, c := range child {
				mark(c, "HISTORY_CORRECTION_BRANCH_CONFLICT")
			}
		}
	}
	// Linear graph traversal avoids quadratic work for long correction chains.
	colors := map[string]uint8{}
	for id := range all {
		if colors[id] != 0 {
			continue
		}
		path := []string{}
		current := id
		for current != "" && colors[current] == 0 {
			r, ok := all[current]
			if !ok {
				break
			}
			colors[current] = 1
			path = append(path, current)
			current = r.corrects
		}
		if colors[current] == 1 {
			for _, p := range path {
				mark(p, "HISTORY_CORRECTION_CYCLE")
			}
		}
		for _, p := range path {
			colors[p] = 2
		}
	}
	queue := []string{}
	for id := range bad {
		queue = append(queue, id)
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		related := append([]string{}, children[id]...)
		if parent := all[id].corrects; parent != "" {
			related = append(related, parent)
		}
		for _, other := range related {
			if _, ok := all[other]; ok && !bad[other] {
				bad[other] = true
				queue = append(queue, other)
			}
		}
	}
	selected := map[string]bool{}
	superseded := []string{}
	for id := range all {
		if bad[id] {
			continue
		}
		if len(children[id]) > 0 {
			superseded = append(superseded, id)
		} else {
			selected[id] = true
		}
	}
	sort.Strings(superseded)
	return selected, superseded, issues
}

func unique(in []string) []string {
	m := map[string]bool{}
	for _, s := range in {
		if s != "" {
			m[s] = true
		}
	}
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

type sourceKey struct{ system, id string }

func currentRef(ref SourceRef, states map[sourceKey]SourceState, at time.Time) string {
	s, ok := states[sourceKey{ref.SourceSystem, ref.SourceID}]
	if !ok {
		return "HISTORY_SOURCE_STATE_MISSING"
	}
	if s.Binding != ref.Binding || !versionAtLeast(s.SourceRegistrationVersion, ref.SourceRegistrationVersion) || s.ConfigHash != ref.ConfigHash {
		return "HISTORY_SOURCE_CONFIGURATION_CHANGED"
	}
	if s.Status != "ACTIVE" {
		return "HISTORY_SOURCE_" + s.Status
	}
	if s.CheckedAt.Before(at.Add(-5*time.Minute)) || s.CheckedAt.After(at.Add(5*time.Second)) {
		return "HISTORY_SOURCE_STATE_STALE"
	}
	return ""
}
func addIssue(a *Analysis, id, reason string) {
	a.Issues = append(a.Issues, Issue{id, reason})
	a.ReasonCodes = append(a.ReasonCodes, reason)
}

func Analyze(input Input) (Analysis, error) {
	in := normalizedInput(input)
	r := in.Registration
	if err := ValidateRegistration(r); err != nil {
		return Analysis{}, err
	}
	if in.AsOf.IsZero() || in.Start.IsZero() || !in.End.After(in.Start) || in.End.After(in.AsOf) || in.End.Sub(in.Start) > 92*24*time.Hour || len(in.Observations) > 100000 || len(in.Demand) > 250000 || len(in.Sources) > 1024 {
		return Analysis{}, invalid("HISTORY_ANALYSIS_WINDOW_INVALID")
	}
	if in.Definition.Binding != r.Binding {
		return Analysis{}, invalid("HISTORY_DEMAND_BINDING_INVALID")
	}
	a := Analysis{SchemaVersion: SchemaVersion, Purpose: "READ_ONLY_FLEET_HISTORY_ANALYSIS", Status: "BLOCKED", Binding: r.Binding, FleetID: r.FleetID, ASGARN: r.ASGARN, RegistrationID: r.ID, RegistrationVersion: r.Version, RegistrationHash: RegistrationHash(r), DefinitionID: in.Definition.ID, DefinitionVersion: in.Definition.Version, DefinitionHash: DefinitionHash(in.Definition), InputHash: InputHash(in), Start: in.Start, End: in.End, AsOf: in.AsOf, MembershipStatus: "INTERVAL_OWNERSHIP_UNPROVEN", Observations: []MembershipObservation{}, SupersededIDs: []string{}, MembershipGaps: []Gap{{in.Start, in.End, "HISTORICAL_MEMBERSHIP_INTERVAL_OWNERSHIP_UNPROVEN"}}, ObservationGaps: []Gap{}, Sources: in.Sources, Issues: []Issue{}, ReasonCodes: []string{"HISTORICAL_MEMBERSHIP_INTERVAL_OWNERSHIP_UNPROVEN", "CAPTURE_PROVENANCE_IS_NOT_HISTORICAL_COVERAGE"}}
	states := map[sourceKey]SourceState{}
	for _, s := range in.Sources {
		if s.Binding != r.Binding || !text(s.SourceID, 256) || (s.SourceSystem != "AWS_SOURCE_CONNECTION" && s.SourceSystem != "ACTIVITY_SOURCE" && s.SourceSystem != "NATIVE_TELEMETRY_CONNECTION") || !sourceVersionValid(s.SourceSystem, s.SourceRegistrationVersion) || !hashPattern.MatchString(s.ConfigHash) || s.CheckedAt.IsZero() || (s.Status != "ACTIVE" && s.Status != "REVOKED" && s.Status != "SUPERSEDED" && s.Status != "DEGRADED") {
			return Analysis{}, invalid("HISTORY_SOURCE_SNAPSHOT_INVALID")
		}
		key := sourceKey{s.SourceSystem, s.SourceID}
		if _, exists := states[key]; exists {
			return Analysis{}, invalid("HISTORY_SOURCE_STATE_AMBIGUOUS")
		}
		states[key] = s
	}
	valid := map[string]MembershipObservation{}
	records := []lineage{}
	for _, o := range in.Observations {
		if o.Source.Binding != r.Binding {
			return Analysis{}, invalid("HISTORY_OBSERVATION_SCOPE_INVALID")
		}
		for _, m := range o.Members {
			if m.Hardware != nil && m.Hardware.Binding != r.Binding {
				return Analysis{}, invalid("HISTORY_MEMBER_SCOPE_INVALID")
			}
		}
		if err := ValidateObservation(r, o); err != nil {
			addIssue(&a, o.ID, err.Error())
			continue
		}
		if o.ReceivedAt.After(in.AsOf.Add(5*time.Second)) || o.ObservedAt.After(in.AsOf.Add(5*time.Second)) {
			addIssue(&a, o.ID, "HISTORY_OBSERVATION_FUTURE")
			continue
		}
		records = append(records, lineage{o.ID, o.CorrectsID, o.ObservedAt.Format(time.RFC3339Nano), ObservationHash(o), o.ReceivedAt})
		valid[o.ID] = o
	}
	selected, superseded, issues := resolve(records)
	a.SupersededIDs = superseded
	for _, issue := range issues {
		addIssue(&a, issue.RecordID, issue.ReasonCode)
	}
	points := map[string][]MembershipObservation{}
	for id := range selected {
		o := valid[id]
		if o.ObservedAt.Before(in.Start) || o.ObservedAt.After(in.End) {
			continue
		}
		reason := currentRef(o.Source, states, in.AsOf)
		for _, m := range o.Members {
			if m.Hardware != nil {
				if code := currentRef(*m.Hardware, states, in.AsOf); code != "" {
					addIssue(&a, id, code)
				}
			}
			if m.Hardware == nil {
				addIssue(&a, id, "HISTORY_MEMBER_HARDWARE_UNOBSERVED")
			}
			if m.LaunchTime == nil {
				addIssue(&a, id, "HISTORY_MEMBER_LAUNCH_TIME_UNOBSERVED")
			}
		}
		if reason != "" {
			addIssue(&a, id, reason)
			continue
		}
		key := o.ObservedAt.Format(time.RFC3339Nano)
		points[key] = append(points[key], o)
	}
	incarnations := map[string]string{}
	pointTimes := make([]string, 0, len(points))
	for key := range points {
		pointTimes = append(pointTimes, key)
	}
	sort.Strings(pointTimes)
	for _, key := range pointTimes {
		group := points[key]
		conflict := false
		first := memberSignature(group[0].Members)
		for _, o := range group[1:] {
			if memberSignature(o.Members) != first {
				conflict = true
			}
		}
		if conflict {
			for _, o := range group {
				addIssue(&a, o.ID, "HISTORY_POINT_MEMBERSHIP_CONFLICT")
			}
			continue
		}
		for _, o := range group {
			a.Observations = append(a.Observations, o)
			for _, m := range o.Members {
				if m.LaunchTime == nil || m.Hardware == nil {
					continue
				}
				incarnation := m.LaunchTime.Format(time.RFC3339Nano)
				if old, ok := incarnations[m.InstanceID]; ok && old != incarnation {
					addIssue(&a, o.ID, "HISTORY_INSTANCE_INCARNATION_CONFLICT")
				}
				incarnations[m.InstanceID] = incarnation
			}
		}
	}
	sort.Slice(a.Observations, func(i, j int) bool {
		p, q := a.Observations[i], a.Observations[j]
		if !p.ObservedAt.Equal(q.ObservedAt) {
			return p.ObservedAt.Before(q.ObservedAt)
		}
		return p.ID < q.ID
	})
	if len(a.Observations) == 0 {
		a.ReasonCodes = append(a.ReasonCodes, "HISTORY_MEMBERSHIP_POINTS_MISSING")
	}
	previous := in.Start
	limit := time.Duration(r.MaxGapSeconds) * time.Second
	for _, o := range a.Observations {
		if o.ObservedAt.Sub(previous) > limit {
			a.ObservationGaps = append(a.ObservationGaps, Gap{previous, o.ObservedAt, "HISTORY_POINT_CADENCE_GAP"})
		}
		previous = o.ObservedAt
	}
	if in.End.Sub(previous) > limit {
		a.ObservationGaps = append(a.ObservationGaps, Gap{previous, in.End, "HISTORY_POINT_CADENCE_GAP"})
	}
	if len(a.ObservationGaps) > 0 {
		a.ReasonCodes = append(a.ReasonCodes, "HISTORY_POINT_CADENCE_GAP")
	}
	a.Demand = analyzeDemand(in, states)
	a.ReasonCodes = append(a.ReasonCodes, a.Demand.ReasonCodes...)
	for _, issue := range a.Issues {
		a.ReasonCodes = append(a.ReasonCodes, issue.ReasonCode)
	}
	a.ReasonCodes = unique(a.ReasonCodes)
	sort.Slice(a.Issues, func(i, j int) bool {
		p, q := a.Issues[i], a.Issues[j]
		if p.RecordID != q.RecordID {
			return p.RecordID < q.RecordID
		}
		return p.ReasonCode < q.ReasonCode
	})
	if len(a.Issues) > 1 {
		out := a.Issues[:1]
		for _, issue := range a.Issues[1:] {
			if issue != out[len(out)-1] {
				out = append(out, issue)
			}
		}
		a.Issues = out
	}
	a.Hash = SnapshotHash(a)
	return a, nil
}
func memberSignature(ms []Member) string {
	type member struct {
		InstanceID string
		LaunchTime *time.Time
		Template   string
		Version    uint64
		Resource   string
	}
	out := make([]member, 0, len(ms))
	for _, m := range ms {
		out = append(out, member{m.InstanceID, m.LaunchTime, m.LaunchTemplateID, m.LaunchTemplateVersion, m.ResourceID})
	}
	return digest(out)
}

func analyzeDemand(in Input, states map[sourceKey]SourceState) DemandAnalysis {
	d := in.Definition
	out := DemandAnalysis{Status: "UNKNOWN", MeaningBasis: "DECLARED_COMPLETED_WORK_SEMANTICS", Unit: d.Unit, Segments: []DemandSegment{}, Gaps: []Gap{}, ReasonCodes: []string{"DEMAND_SEMANTICS_REQUIRE_INDEPENDENT_SOURCE_VALIDATION"}}
	fail := func(reason string) { out.ReasonCodes = append(out.ReasonCodes, reason) }
	if err := ValidateDemandDefinition(in.Registration, d); err != nil {
		fail(err.Error())
		out.Gaps = []Gap{{in.Start, in.End, err.Error()}}
		out.ReasonCodes = unique(out.ReasonCodes)
		return out
	}
	valid := map[string]DemandSample{}
	records := []lineage{}
	fault := false
	for _, s := range in.Demand {
		if err := ValidateDemandSample(in.Registration, d, s); err != nil {
			fail(err.Error())
			fault = true
			continue
		}
		if s.ReceivedAt.After(in.AsOf.Add(5*time.Second)) || s.Time.After(in.AsOf.Add(5*time.Second)) {
			fail("DEMAND_SAMPLE_FUTURE")
			fault = true
			continue
		}
		records = append(records, lineage{s.ID, s.CorrectsID, s.Start.Format(time.RFC3339Nano) + "/" + s.Time.Format(time.RFC3339Nano), SampleHash(s), s.ReceivedAt})
		valid[s.ID] = s
	}
	selected, _, issues := resolve(records)
	for _, issue := range issues {
		fail(issue.ReasonCode)
		fault = true
	}
	points := map[string][]DemandSample{}
	for id := range selected {
		s := valid[id]
		if reason := currentRef(s.Source, states, in.AsOf); reason != "" {
			fail(reason)
			fault = true
			continue
		}
		if !s.Time.After(in.End) {
			points[s.Time.Format(time.RFC3339Nano)] = append(points[s.Time.Format(time.RFC3339Nano)], s)
		}
	}
	ordered := []DemandSample{}
	for _, group := range points {
		first := group[0]
		conflict := false
		for _, s := range group[1:] {
			if !sameDemandPoint(first, s) {
				conflict = true
			}
		}
		if conflict {
			fail("DEMAND_NATIVE_POINT_CONFLICT")
			fault = true
			continue
		}
		sort.Slice(group, func(i, j int) bool { return group[i].ID < group[j].ID })
		ordered = append(ordered, group[0])
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Time.Before(ordered[j].Time) })
	var previous *DemandSample
	for _, s := range ordered {
		start := s.Start
		ids := []string{s.ID}
		var units *big.Int
		reason := ""
		if d.Temporality == "CUMULATIVE" {
			if previous == nil {
				copy := s
				previous = &copy
				continue
			}
			start = previous.Time
			ids = []string{previous.ID, s.ID}
			if !sameEpoch(s.Epoch, previous.Epoch) {
				reason = "DEMAND_COUNTER_EPOCH_CHANGED"
			} else if previous.Value == nil || s.Value == nil {
				reason = "DEMAND_OBSERVATION_MISSING"
			} else {
				current, _ := count(*s.Value)
				old, _ := count(*previous.Value)
				units = new(big.Int).Sub(current, old)
				if units.Sign() < 0 {
					units = nil
					reason = "DEMAND_COUNTER_RESET_UNKNOWN"
				}
			}
		} else if s.Value == nil {
			reason = "DEMAND_OBSERVATION_MISSING"
		} else {
			units, _ = count(*s.Value)
		}
		copy := s
		previous = &copy
		if !s.Time.After(in.Start) || !start.Before(in.End) {
			continue
		}
		segment := DemandSegment{start, s.Time, "OBSERVED", nil, ids, "DEMAND_NATIVE_COUNT_OBSERVED"}
		if start.Before(in.Start) || s.Time.After(in.End) {
			reason = "DEMAND_WINDOW_BOUNDARY_NOT_OBSERVED"
		}
		if s.Time.Sub(start) > time.Duration(d.MaxGapSeconds)*time.Second {
			reason = "DEMAND_OBSERVATION_GAP"
		}
		if reason != "" {
			segment.Status = "UNKNOWN"
			segment.ReasonCode = reason
			fail(reason)
			fault = true
		} else if units != nil {
			v := units.String()
			segment.Units = &v
		}
		out.Segments = append(out.Segments, segment)
	}
	// A total is meaningful only over disjoint fully observed native intervals.
	// Overlap/conflict never doubles counts; no rate extrapolation or prorating.
	total := new(big.Int)
	observed := false
	cursor := in.Start
	for i := range out.Segments {
		s := &out.Segments[i]
		if s.Start.Before(cursor) {
			s.Status = "UNKNOWN"
			s.Units = nil
			s.ReasonCode = "DEMAND_INTERVAL_OVERLAP"
			fail(s.ReasonCode)
			fault = true
		}
		if s.Start.After(cursor) {
			end := s.Start
			if end.After(in.End) {
				end = in.End
			}
			out.Gaps = append(out.Gaps, Gap{cursor, end, "DEMAND_OBSERVATION_MISSING"})
			fault = true
		}
		if s.Status == "OBSERVED" && s.Units != nil {
			v, _ := count(*s.Units)
			total.Add(total, v)
			observed = true
		} else {
			start, end := s.Start, s.End
			if start.Before(in.Start) {
				start = in.Start
			}
			if end.After(in.End) {
				end = in.End
			}
			if end.After(start) {
				out.Gaps = append(out.Gaps, Gap{start, end, s.ReasonCode})
			}
		}
		if s.End.After(cursor) {
			cursor = s.End
		}
	}
	if cursor.Before(in.End) {
		out.Gaps = append(out.Gaps, Gap{cursor, in.End, "DEMAND_OBSERVATION_MISSING"})
		fault = true
	}
	if observed {
		v := total.String()
		out.ObservedUnits = &v
	}
	if len(out.Gaps) > 0 {
		fail("DEMAND_WINDOW_HAS_UNKNOWN_INTERVALS")
	}
	if observed && !fault && len(out.Gaps) == 0 {
		out.Status = "OBSERVED"
		v := total.String()
		out.WindowUnits = &v
	}
	out.ReasonCodes = unique(out.ReasonCodes)
	return out
}
func sameDemandPoint(a, b DemandSample) bool {
	if !a.Start.Equal(b.Start) || !a.Time.Equal(b.Time) || !sameEpoch(a.Epoch, b.Epoch) || a.Partition != b.Partition {
		return false
	}
	return a.Value == nil && b.Value == nil || a.Value != nil && b.Value != nil && *a.Value == *b.Value
}
func sameEpoch(a, b *time.Time) bool {
	return a == nil && b == nil || a != nil && b != nil && a.Equal(*b)
}
