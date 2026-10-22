package network

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

// ParseFlow retains the native capture direction, packet-level addresses,
// service classification and path separately. traffic-path describes egress
// only; it does not on its own establish a NAT or an endpoint route.
func ParseFlow(r Registration, line string) (FlowRow, error) {
	out := FlowRow{}
	values := strings.Fields(line)
	if len(values) != len(r.Fields) {
		return out, errors.New("FLOW_LOG_FIELD_COUNT_MISMATCH")
	}
	f := map[string]string{}
	for i, key := range r.Fields {
		if len(values[i]) > 2048 {
			return out, ErrEvidence
		}
		f[key] = values[i]
	}
	out.Fields = f
	v, e := strconv.Atoi(f["version"])
	if e != nil || v < 2 || v > 10 {
		return out, errors.New("FLOW_LOG_VERSION_UNSUPPORTED")
	}
	clean := func(key string) string {
		if f[key] == "-" {
			return ""
		}
		return f[key]
	}
	out.AccountID = clean("account-id")
	out.Region = clean("region")
	if out.AccountID != "" && out.AccountID != r.AccountID || out.Region != "" && out.Region != r.Region {
		return out, errors.New("FLOW_LOG_SCOPE_MISMATCH")
	}
	out.InterfaceID = clean("interface-id")
	out.ResourceID = clean("resource-id")
	out.VPCID = clean("vpc-id")
	out.SubnetID = clean("subnet-id")
	out.AZID = clean("az-id")
	out.Source = clean("srcaddr")
	out.Destination = clean("dstaddr")
	out.PacketSource = clean("pkt-srcaddr")
	out.PacketDestination = clean("pkt-dstaddr")
	out.SourceService = clean("pkt-src-aws-service")
	out.DestinationService = clean("pkt-dst-aws-service")
	out.Direction = clean("flow-direction")
	out.TrafficPath = clean("traffic-path")
	out.Action = clean("action")
	out.LogStatus = clean("log-status")
	out.Protocol = clean("protocol")
	if out.Protocol != "" {
		if _, e := strconv.ParseUint(out.Protocol, 10, 8); e != nil {
			return out, errors.New("FLOW_LOG_PROTOCOL_INVALID")
		}
	}
	for _, port := range []string{"srcport", "dstport"} {
		if clean(port) != "" {
			if _, e := strconv.ParseUint(f[port], 10, 16); e != nil {
				return out, errors.New("FLOW_LOG_PORT_INVALID")
			}
		}
	}
	for _, scope := range r.ResourceIDs {
		if strings.HasPrefix(scope, "vpc-") && out.VPCID != "" && out.VPCID != scope || strings.HasPrefix(scope, "subnet-") && out.SubnetID != "" && out.SubnetID != scope || strings.HasPrefix(scope, "eni-") && out.InterfaceID != "" && out.InterfaceID != scope {
			return out, errors.New("FLOW_LOG_REGISTERED_RESOURCE_SCOPE_MISMATCH")
		}
	}
	if out.Direction != "" && out.Direction != "ingress" && out.Direction != "egress" {
		return out, errors.New("FLOW_LOG_DIRECTION_INVALID")
	}
	if out.Action != "" && out.Action != "ACCEPT" && out.Action != "REJECT" {
		return out, ErrEvidence
	}
	if out.LogStatus != "OK" && out.LogStatus != "NODATA" && out.LogStatus != "SKIPDATA" {
		return out, ErrEvidence
	}
	for _, ip := range []string{out.Source, out.Destination, out.PacketSource, out.PacketDestination} {
		if ip != "" {
			if _, e = netip.ParseAddr(ip); e != nil {
				return out, ErrEvidence
			}
		}
	}
	if out.TrafficPath != "" {
		p, e := strconv.Atoi(out.TrafficPath)
		if e != nil || p < 1 || p > 100 {
			return out, ErrEvidence
		}
	}
	parseCount := func(key string) (*uint64, error) {
		if clean(key) == "" {
			return nil, nil
		}
		v, e := strconv.ParseUint(f[key], 10, 64)
		if e != nil {
			return nil, e
		}
		return &v, nil
	}
	if out.Bytes, e = parseCount("bytes"); e != nil {
		return out, ErrEvidence
	}
	if out.Packets, e = parseCount("packets"); e != nil {
		return out, ErrEvidence
	}
	parseTime := func(key string) (*time.Time, error) {
		if clean(key) == "" {
			return nil, nil
		}
		v, e := strconv.ParseInt(f[key], 10, 64)
		if e != nil || v < 0 {
			return nil, ErrEvidence
		}
		t := time.Unix(v, 0).UTC()
		return &t, nil
	}
	if out.Start, e = parseTime("start"); e != nil {
		return out, e
	}
	if out.End, e = parseTime("end"); e != nil {
		return out, e
	}
	if out.Start != nil && out.End != nil && out.End.Before(*out.Start) {
		return out, ErrEvidence
	}
	if out.LogStatus == "OK" && (out.Bytes == nil || out.Packets == nil || out.Start == nil || out.End == nil || out.InterfaceID == "" || out.Action == "") {
		return out, errors.New("FLOW_LOG_OK_RECORD_INCOMPLETE")
	}
	// Deliberately do not infer destination classification from DNS/IP prefixes.
	key := model.Document{"interface_id": out.InterfaceID, "resource_id": out.ResourceID, "vpc_id": out.VPCID, "subnet_id": out.SubnetID, "az_id": out.AZID, "source_service": out.SourceService, "destination_service": out.DestinationService, "direction": out.Direction, "traffic_path": out.TrafficPath, "action": out.Action, "log_status": out.LogStatus, "protocol": out.Protocol}
	out.CohortID = Hash(key)
	return out, nil
}

type chunkReader struct {
	ctx                     context.Context
	in                      io.Reader
	archive                 Archive
	tenant, generation, key string
	chunk                   []byte
	index                   int
	hash                    hash.Hash
	size                    int64
	refs                    []model.Document
}

func (c *chunkReader) Read(p []byte) (int, error) {
	n, e := c.in.Read(p)
	if n > 0 {
		c.hash.Write(p[:n])
		c.size += int64(n)
		remaining := p[:n]
		for len(remaining) > 0 {
			take := RawChunkBytes - len(c.chunk)
			if take > len(remaining) {
				take = len(remaining)
			}
			c.chunk = append(c.chunk, remaining[:take]...)
			remaining = remaining[take:]
			if len(c.chunk) == RawChunkBytes {
				if err := c.flush(); err != nil {
					return n, err
				}
			}
		}
	}
	return n, e
}
func (c *chunkReader) flush() error {
	if len(c.chunk) == 0 {
		return nil
	}
	if c.index >= 4096 {
		return errors.New("FLOW_OBJECT_CHUNK_LIMIT")
	}
	id := Hash(model.Document{"generation": c.generation, "key": c.key, "chunk": c.index, "sha256": BytesHash(c.chunk)})
	ref, e := c.archive.Archive(c.ctx, c.tenant, "network-flow-chunk-v1", id, c.chunk)
	if e != nil {
		return e
	}
	read, e := c.archive.Read(c.ctx, c.tenant, ref)
	if e != nil || BytesHash(read) != BytesHash(c.chunk) {
		return errors.New("FLOW_ARCHIVE_READBACK_MISMATCH")
	}
	c.refs = append(c.refs, model.Document{"index": c.index, "size": len(c.chunk), "sha256": BytesHash(c.chunk), "archive": ref})
	c.index++
	c.chunk = c.chunk[:0]
	return nil
}

// IngestFlow replays deterministic batches on resumption. A batch's identity is
// independent of ClickHouse's deduplication window; consumers query only a
// published generation and unique row IDs. No partial generation is complete.
// VPC Flow Logs are best effort: complete delivery is NOT full traffic coverage.
func IngestFlow(ctx context.Context, r Registration, objects []ObjectRef, reader ObjectReader, archive Archive, facts Facts, checkpoint Checkpoint) (Generation, error) {
	out := Generation{SourceID: r.ID, SourceVersion: r.Version, Scope: Scope{r.TenantID, r.AccountID, r.Region}, Cohorts: []model.Document{}, SourceRefs: []model.Document{}, Coverage: model.Document{"status": "UNKNOWN", "complete_traffic_census": false, "missing_is_zero": false}, Complete: false}
	if ValidateRegistration(r) != nil || reader == nil || archive == nil || facts == nil || len(objects) == 0 || len(objects) > 10000 {
		return out, ErrEvidence
	}
	refs := append([]ObjectRef{}, objects...)
	sort.Slice(refs, func(i, j int) bool { return refs[i].Key < refs[j].Key })
	seen := map[string]bool{}
	for _, ref := range refs {
		if seen[ref.Key] || !strings.HasPrefix(ref.Key, r.Prefix) || strings.Contains(ref.Key, "..") || !strings.HasSuffix(ref.Key, ".gz") || ref.VersionID == "" || ref.VersionID == "null" || !hashID.MatchString(ref.SHA256) || ref.Size <= 0 {
			return out, errors.New("FLOW_OBJECT_PIN_REQUIRED")
		}
		seen[ref.Key] = true
	}
	boundary, e := reader.FlowBoundary(ctx, r)
	if e != nil {
		return out, e
	}
	if model.String(boundary, "configuration_hash") == "" || model.String(boundary, "writer_policy_hash") == "" || model.String(boundary, "versioning") != "Enabled" {
		return out, errors.New("FLOW_BOUNDARY_UNPROVEN")
	}
	out.ID = Hash(model.Document{"contract": "NETWORK_FLOW_GENERATION_V1", "registration": r, "objects": refs, "configuration_hash": boundary["configuration_hash"], "writer_policy_hash": boundary["writer_policy_hash"]})
	if checkpoint != nil {
		old, e := checkpoint.Load(ctx, r.TenantID, out.ID)
		if e != nil {
			return out, e
		}
		if old != nil && model.String(old, "generation_id") != out.ID {
			return out, ErrEvidence
		}
	}
	cohorts := map[string]model.Document{}
	allHash := sha256.New()
	batchHash := sha256.New()
	batch := []FlowRow{}
	batchNumber := 0
	unknownRecords, skippedRecords := int64(0), int64(0)
	var minStart, maxEnd *time.Time
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		digest := Hash(batch)
		batchID := Hash(model.Document{"generation": out.ID, "number": batchNumber, "rows": digest})
		receipt, e := facts.WriteNetworkRows(ctx, out.Scope, out.ID, batchID, batch)
		if e != nil {
			return e
		}
		if model.String(receipt, "row_digest") != digest || fmt.Sprint(receipt["rows"]) != strconv.Itoa(len(batch)) {
			return errors.New("FLOW_ANALYTICS_RECEIPT_MISMATCH")
		}
		batchHash.Write([]byte(batchID))
		batchNumber++
		batch = batch[:0]
		return nil
	}
	for _, ref := range refs {
		object, e := reader.OpenFlowObject(ctx, r, ref.Key, ref.VersionID)
		if e != nil {
			return out, e
		}
		if object.Body == nil || object.Bucket != r.ReportBucket || object.Key != ref.Key || object.VersionID != ref.VersionID || object.Length < -1 || object.Length >= 0 && object.Length != ref.Size {
			if object.Body != nil {
				object.Body.Close()
			}
			return out, errors.New("FLOW_OBJECT_CHANGED")
		}
		cr := &chunkReader{ctx: ctx, in: object.Body, archive: archive, tenant: r.TenantID, generation: out.ID, key: ref.Key, chunk: make([]byte, 0, RawChunkBytes), hash: sha256.New(), refs: []model.Document{}}
		gz, e := gzip.NewReader(cr)
		if e != nil {
			object.Body.Close()
			return out, errors.New("FLOW_GZIP_INVALID")
		}
		scanner := bufio.NewScanner(gz)
		scanner.Buffer(make([]byte, 64<<10), 128<<10)
		lineNumber := 0
		for scanner.Scan() {
			if ctx.Err() != nil {
				gz.Close()
				object.Body.Close()
				return out, ctx.Err()
			}
			line := scanner.Text()
			if lineNumber == 0 && strings.Join(strings.Fields(line), " ") == strings.Join(r.Fields, " ") {
				lineNumber++
				continue
			}
			row, e := ParseFlow(r, line)
			if e != nil {
				gz.Close()
				object.Body.Close()
				return out, e
			}
			row.ID = Hash(model.Document{"flow_log_id": r.FlowLogID, "fields": row.Fields})
			allHash.Write([]byte(row.ID))
			lineNumber++
			out.Rows++
			if row.LogStatus == "SKIPDATA" {
				skippedRecords++
			}
			if row.LogStatus != "OK" || row.AccountID == "" || row.Region == "" || row.Direction == "" || row.DestinationService == "" && row.SourceService == "" {
				unknownRecords++
			}
			if row.Start != nil && (minStart == nil || row.Start.Before(*minStart)) {
				v := *row.Start
				minStart = &v
			}
			if row.End != nil && (maxEnd == nil || row.End.After(*maxEnd)) {
				v := *row.End
				maxEnd = &v
			}
			cohort := cohorts[row.CohortID]
			if cohort == nil {
				if len(cohorts) >= MaxCohorts {
					gz.Close()
					object.Body.Close()
					return out, errors.New("FLOW_BOUNDED_COHORT_LIMIT")
				}
				cohort = model.Document{"id": row.CohortID, "interface_id": row.InterfaceID, "resource_id": row.ResourceID, "vpc_id": row.VPCID, "subnet_id": row.SubnetID, "az_id": row.AZID, "source_service": row.SourceService, "destination_service": row.DestinationService, "flow_direction": row.Direction, "traffic_path": row.TrafficPath, "action": row.Action, "log_status": row.LogStatus, "protocol": row.Protocol, "bytes": uint64(0), "packets": uint64(0), "records": int64(0), "unknown_byte_records": int64(0), "destination_addresses": []string{}, "destination_addresses_complete": true, "source_addresses": []string{}, "source_addresses_complete": true, "complete_traffic_census": false}
				cohorts[row.CohortID] = cohort
			}
			cohort["records"] = cohort["records"].(int64) + 1
			if row.Bytes == nil {
				cohort["unknown_byte_records"] = cohort["unknown_byte_records"].(int64) + 1
			} else {
				prior := cohort["bytes"].(uint64)
				if ^uint64(0)-prior < *row.Bytes {
					gz.Close()
					object.Body.Close()
					return out, ErrEvidence
				}
				cohort["bytes"] = prior + *row.Bytes
			}
			if row.Packets != nil {
				prior := cohort["packets"].(uint64)
				if ^uint64(0)-prior < *row.Packets {
					gz.Close()
					object.Body.Close()
					return out, ErrEvidence
				}
				cohort["packets"] = prior + *row.Packets
			}
			address := row.PacketDestination
			if address == "" {
				address = row.Destination
			}
			addresses := cohort["destination_addresses"].([]string)
			found := false
			for _, a := range addresses {
				if a == address {
					found = true
				}
			}
			if !found && address != "" {
				if len(addresses) < 16 {
					cohort["destination_addresses"] = append(addresses, address)
				} else {
					cohort["destination_addresses_complete"] = false
				}
			}
			source := row.PacketSource
			if source == "" {
				source = row.Source
			}
			sources := cohort["source_addresses"].([]string)
			known := false
			for _, a := range sources {
				if a == source {
					known = true
				}
			}
			if !known && source != "" {
				if len(sources) < 16 {
					cohort["source_addresses"] = append(sources, source)
				} else {
					cohort["source_addresses_complete"] = false
				}
			}
			batch = append(batch, row)
			if len(batch) == FlowBatchRows {
				if e = flush(); e != nil {
					gz.Close()
					object.Body.Close()
					return out, e
				}
			}
		}
		scanErr := scanner.Err()
		gzErr := gz.Close()
		_, drainErr := io.Copy(io.Discard, cr)
		closeErr := object.Body.Close()
		if scanErr != nil || gzErr != nil || drainErr != nil || closeErr != nil {
			return out, errors.New("FLOW_STREAM_INCOMPLETE")
		}
		if e = cr.flush(); e != nil {
			return out, e
		}
		if cr.size != ref.Size || hex.EncodeToString(cr.hash.Sum(nil)) != ref.SHA256 {
			return out, errors.New("FLOW_OBJECT_HASH_MISMATCH")
		}
		out.SourceRefs = append(out.SourceRefs, model.Document{"type": "FLOW_OBJECT", "key": ref.Key, "version_id": ref.VersionID, "sha256": ref.SHA256, "size": ref.Size, "chunks": cr.refs})
		if e = flush(); e != nil {
			return out, e
		}
		if checkpoint != nil {
			if e = checkpoint.Save(ctx, r.TenantID, out.ID, model.Document{"generation_id": out.ID, "validated_object": ref.Key, "rows": out.Rows, "next_batch": batchNumber, "status": "INGESTING"}); e != nil {
				return out, e
			}
		}
	}
	// Re-read the commissioned boundary after streaming. Revocation or a changed
	// source/writer configuration prevents this generation's publication.
	after, e := reader.FlowBoundary(ctx, r)
	if e != nil || model.String(after, "configuration_hash") != model.String(boundary, "configuration_hash") || model.String(after, "writer_policy_hash") != model.String(boundary, "writer_policy_hash") {
		return out, errors.New("FLOW_BOUNDARY_CHANGED")
	}
	for _, c := range cohorts {
		c["bytes"] = strconv.FormatUint(c["bytes"].(uint64), 10)
		c["packets"] = strconv.FormatUint(c["packets"].(uint64), 10)
		c["generation_id"] = out.ID
		c["attribution_quality"] = "OBSERVED_PARTIAL_BEST_EFFORT"
		out.Cohorts = append(out.Cohorts, c)
	}
	sort.Slice(out.Cohorts, func(i, j int) bool { return model.String(out.Cohorts[i], "id") < model.String(out.Cohorts[j], "id") })
	out.PopulationHash = hex.EncodeToString(allHash.Sum(nil))
	out.Coverage = model.Document{"status": "DELIVERY_VALIDATED_BEST_EFFORT_TRAFFIC", "complete_traffic_census": false, "missing_is_zero": false, "flow_log_id": r.FlowLogID, "resource_ids": r.ResourceIDs, "traffic_type": r.TrafficType, "max_aggregation_seconds": r.MaxAggregationSeconds, "unknown_attribution_records": unknownRecords, "skipdata_records": skippedRecords, "start": minStart, "end": maxEnd, "configuration_hash": boundary["configuration_hash"], "writer_policy_hash": boundary["writer_policy_hash"], "analytics_batches": batchNumber, "analytics_batch_digest": hex.EncodeToString(batchHash.Sum(nil))}
	out.Complete = true
	if checkpoint != nil {
		if e = checkpoint.Save(ctx, r.TenantID, out.ID, model.Document{"generation_id": out.ID, "rows": out.Rows, "status": "VALIDATED", "population_hash": out.PopulationHash}); e != nil {
			return out, e
		}
	}
	return out, nil
}
