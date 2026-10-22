package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/network"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

type networkArchiveAdapter struct{ *native.Storage }

// The immutable content hash binds archived bytes, not a re-serialization of
// typed structs into maps. UseNumber preserves native integer observations.
func decodeNetworkSnapshot(raw []byte, contentHash, configHash string) (model.Document, error) {
	canonical := model.Document{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if network.BytesHash(raw) != contentHash || decoder.Decode(&canonical) != nil || canonical == nil || decoder.Decode(new(any)) != io.EOF || model.String(canonical, "config_hash") != configHash {
		return nil, errors.New("NETWORK_FLOW_TOPOLOGY_BINDING_CHANGED")
	}
	return canonical, nil
}

func (n networkArchiveAdapter) Archive(ctx context.Context, tenant, kind, id string, raw []byte) (model.Document, error) {
	return n.Storage.Archive(ctx, tenant, "wire", "network-"+network.Hash(model.Document{"kind": kind, "id": id}), raw)
}
func networkArchive(ctx context.Context, archive *native.Storage, tenant, kind string, d any) (model.Document, error) {
	raw, e := json.Marshal(d)
	if e != nil || len(raw) > 8<<20 {
		return nil, errors.New("NETWORK_SNAPSHOT_BOUND_EXCEEDED")
	}
	ref, e := archive.Archive(ctx, tenant, "canonical", kind+"-"+network.BytesHash(raw), raw)
	if e != nil {
		return nil, e
	}
	again, e := archive.Read(ctx, tenant, ref)
	if e != nil || network.BytesHash(again) != network.BytesHash(raw) {
		return nil, errors.New("NETWORK_ARCHIVE_READBACK_DIFFERS")
	}
	return ref, nil
}
func networkWire(ctx context.Context, archive *native.Storage, tenant, kind string, raw []byte) (model.Document, error) {
	ref, e := archive.Archive(ctx, tenant, "wire", kind+"-"+network.BytesHash(raw), raw)
	if e != nil {
		return nil, e
	}
	again, e := archive.Read(ctx, tenant, ref)
	if e != nil || network.BytesHash(again) != network.BytesHash(raw) {
		return nil, errors.New("NETWORK_NATIVE_ARCHIVE_DIFFERS")
	}
	return model.Document{"kind": kind, "id": ref["key"], "version": ref["version_id"], "sha256": ref["body_sha256"], "archive": ref}, nil
}
func networkDoc(v any) model.Document {
	raw, _ := json.Marshal(v)
	out := model.Document{}
	_ = json.Unmarshal(raw, &out)
	return out
}
func networkRows(v any) []model.Document {
	raw, _ := json.Marshal(v)
	out := []model.Document{}
	_ = json.Unmarshal(raw, &out)
	return out
}
func networkResource(ctx context.Context, tx *store.Tx, d model.Document, cloudAccountID string, topologyHash string, ref model.Document) (model.Document, error) {
	var id string
	e := tx.QueryRow(ctx, "SELECT id FROM entities WHERE tenant_id=$1 AND kind='resources' AND document->>'provider'='AWS' AND document->>'provider_resource_id'=$2 AND document->>'account_id'=$3 AND document->>'region'=$4", tx.Tenant, d["provider_resource_id"], d["account_id"], d["region"]).Scan(&id)
	r := model.Document{"provider": "AWS", "resource_type": d["resource_type"], "provider_resource_id": d["provider_resource_id"], "account_id": d["account_id"], "region": d["region"], "configuration_authority": "UNKNOWN", "environment": "UNKNOWN", "eligibility": "OBSERVE_ONLY", "owner": nil, "workload_id": nil, "name": d["provider_resource_id"]}
	if e == nil {
		r, e = tx.Get(ctx, "resources", id)
		if e != nil {
			return nil, e
		}
	} else if e != pgx.ErrNoRows {
		return nil, e
	}
	if cloudAccountID != "" {
		r["cloud_account_id"] = cloudAccountID
	}
	r["network_configuration"] = d["network_configuration"]
	r["network_topology_hash"] = topologyHash
	r["network_discovery_ref"] = ref
	r["last_seen_at"] = d["last_seen"]
	r["state"] = d["state"]
	if r["state"] == nil {
		r["state"] = "OBSERVED"
	}
	r["availability_zone"] = d["availability_zone"]
	if id == "" {
		return tx.Create(ctx, "resources", r)
	}
	return tx.Update(ctx, "resources", id, model.Number(r, "version"), r)
}

// PublishNetworkDiscovery persists only bounded snapshots and references. Raw
// native pages and per-period observations are archived/analytical, outside the
// short resource and evidence metadata transactions. Existing owner/workload
// and configuration authority are preserved; tags cannot confer authority.
func PublishNetworkDiscovery(ctx context.Context, db *store.Store, archive *native.Storage, d network.Discovery, cloudAccountID string, metrics map[string]model.Document, prices model.Document) error {
	if network.ValidateScope(d.Scope) != nil || d.RawSHA256 != network.BytesHash(d.Raw) || d.TopologyHash == "" {
		return errors.New("NETWORK_DISCOVERY_BINDING_INVALID")
	}
	ref, e := networkWire(ctx, archive, d.Scope.TenantID, "AWS_NETWORK_TOPOLOGY", d.Raw)
	if e != nil {
		return e
	}
	resources := []model.Document{}
	for _, resource := range d.Resources {
		if resource["account_id"] != d.Scope.AccountID || resource["region"] != d.Scope.Region || model.String(resource, "provider_resource_id") == "" {
			return errors.New("NETWORK_RESOURCE_SCOPE_MISMATCH")
		}
		var persisted model.Document
		e = db.Do(ctx, d.Scope.TenantID, func(tx *store.Tx) error {
			var e error
			persisted, e = networkResource(ctx, tx, resource, cloudAccountID, d.TopologyHash, ref)
			return e
		})
		if e != nil {
			return e
		}
		view := model.Clone(resource)
		view["id"], view["workload_id"], view["owner"], view["configuration_authority"] = persisted["id"], persisted["workload_id"], persisted["owner"], persisted["configuration_authority"]
		resources = append(resources, view)
	}
	topology := model.Document{"resources": resources, "coverage": d.Coverage, "topology_hash": d.TopologyHash, "complete": d.Complete}
	for _, view := range resources {
		kind := model.String(view, "resource_type")
		if kind != "NAT_GATEWAY" && kind != "ELASTIC_IP" && kind != "PUBLIC_IPV4" && kind != "VPC" {
			continue
		}
		var resource model.Document
		e = db.Do(ctx, d.Scope.TenantID, func(tx *store.Tx) error {
			var e error
			resource, e = tx.Get(ctx, "resources", model.String(view, "id"))
			return e
		})
		if e != nil {
			return e
		}
		observation := metrics[model.String(view, "provider_resource_id")]
		if observation == nil {
			observation = model.Document{"status": "UNAVAILABLE", "reason_code": "NAT_TELEMETRY_NOT_OBSERVED", "coverage": []model.Document{}, "totals": model.Document{}, "maxima": model.Document{}}
		}
		sourceRefs := []model.Document{ref}
		if metricRef := networkDoc(observation["source_ref"]); len(metricRef) > 0 {
			sourceRefs = append(sourceRefs, metricRef)
		}
		if priceRef := networkDoc(prices["source_ref"]); len(priceRef) > 0 {
			sourceRefs = append(sourceRefs, priceRef)
		}
		canonical := model.Document{"schema_version": "1", "resource_id": resource["id"], "account_id": d.Scope.AccountID, "region": d.Scope.Region, "config_hash": service.NetworkConfigurationHash(resource), "observed_at": d.CollectedAt, "source_version": d.RawSHA256, "topology": topology, "metrics": observation, "flows": model.Document{"complete": false, "coverage": model.Document{"status": "FLOW_LOGS_NOT_COMMISSIONED", "complete_traffic_census": false, "missing_is_zero": false}, "cohorts": []model.Document{}}, "price_dimensions": prices["dimensions"], "pricing_status": prices["status"], "source_refs": sourceRefs, "source_bindings": []model.Document{}}
		ref, e := networkArchive(ctx, archive, d.Scope.TenantID, "network-evaluation", canonical)
		if e != nil {
			return e
		}
		if e = db.Do(ctx, d.Scope.TenantID, func(tx *store.Tx) error {
			current, e := tx.Get(ctx, "resources", model.String(resource, "id"))
			if e != nil {
				return e
			}
			if service.NetworkConfigurationHash(current) != canonical["config_hash"] {
				return errors.New("NETWORK_TOPOLOGY_CHANGED_DURING_PUBLICATION")
			}
			_, e = tx.NetworkEvidenceCreate(ctx, model.String(resource, "id"), "", canonical, ref)
			return e
		}); e != nil {
			return e
		}
	}
	return nil
}
func networkMetricSummary(ctx context.Context, archive *native.Storage, reader *provider.AWS, scope network.Scope, d model.Document) (model.Document, error) {
	end := time.Now().UTC().Truncate(24 * time.Hour)
	selection := network.MetricSelection{NATGatewayID: model.String(d, "provider_resource_id"), Start: end.Add(-30 * 24 * time.Hour), End: end, PeriodSeconds: 3600}
	zones := []string{""}
	if d["availability_mode"] == "regional" {
		zones = []string{}
		seen := map[string]bool{}
		for _, address := range networkRows(d["addresses"]) {
			az := model.String(address, "availability_zone")
			if az != "" && !seen[az] {
				zones = append(zones, az)
				seen[az] = true
			}
		}
		sort.Strings(zones)
	}
	if len(zones) == 0 {
		return nil, errors.New("REGIONAL_NAT_AZ_FOOTPRINT_UNKNOWN")
	}
	totals, maxima := map[string]*big.Rat{}, map[string]*big.Rat{}
	coverage := []model.Document{}
	raws := []model.Document{}
	seriesID := ""
	maxByZone := map[string]map[string]*big.Rat{}
	for _, zone := range zones {
		selection.AvailabilityZone = zone
		observed, e := reader.NetworkNATMetrics(ctx, scope, selection)
		if e != nil {
			return nil, e
		}
		if e = archive.WriteNetworkMetrics(ctx, scope, observed.RawSHA256, observed.Metrics); e != nil {
			return nil, e
		}
		ref, e := networkWire(ctx, archive, scope.TenantID, "AWS_NAT_CLOUDWATCH", observed.Raw)
		if e != nil {
			return nil, e
		}
		raws = append(raws, ref)
		seriesID = observed.RawSHA256
		maxByZone[zone] = map[string]*big.Rat{}
		for _, c := range observed.Coverage {
			c["availability_zone"] = zone
			coverage = append(coverage, c)
		}
		for _, point := range observed.Metrics {
			if point["observed"] != true {
				continue
			}
			name := model.String(point, "metric")
			n, ok := new(big.Rat).SetString(model.String(point, "value"))
			if !ok {
				return nil, errors.New("NETWORK_METRIC_NUMBER_INVALID")
			}
			if point["statistic"] == "Sum" {
				if totals[name] == nil {
					totals[name] = new(big.Rat)
				}
				totals[name].Add(totals[name], n)
			} else {
				if maxByZone[zone][name] == nil || n.Cmp(maxByZone[zone][name]) > 0 {
					maxByZone[zone][name] = n
				}
			}
		}
	}
	for _, m := range maxByZone {
		for name, n := range m {
			if maxima[name] == nil {
				maxima[name] = new(big.Rat)
			}
			maxima[name].Add(maxima[name], n)
		}
	}
	sum, max := model.Document{}, model.Document{}
	for name, n := range totals {
		sum[name] = n.FloatString(12)
	}
	for name, n := range maxima {
		max[name] = n.FloatString(12)
	}
	// Regional current addresses do not establish historical AZ footprint. The
	// native per-AZ series and this blocker remain explicit, never a zero census.
	if d["availability_mode"] == "regional" {
		coverage = append(coverage, model.Document{"metric": "RegionalAvailabilityZoneFootprint", "status": "UNKNOWN", "reason_code": "REGIONAL_NAT_HISTORICAL_AZ_FOOTPRINT_UNKNOWN", "missing_is_zero": false})
	}
	summary := model.Document{"status": "OBSERVED", "selection": selection, "coverage": coverage, "totals": sum, "maxima": max, "source_version": seriesID, "source_refs": raws, "byte_count_basis": "INPUT_PAIR_ONLY_FOR_TOTALS"}
	ref, e := networkArchive(ctx, archive, scope.TenantID, "network-metric-summary", summary)
	if e != nil {
		return nil, e
	}
	summary["source_ref"] = model.Document{"kind": "AWS_NAT_METRICS_SUMMARY", "id": ref["key"], "version": ref["version_id"], "sha256": ref["body_sha256"], "archive": ref}
	return summary, nil
}

func readNetworkEvaluationInputs(ctx context.Context, a *Activities, archive *native.Storage, reader *provider.AWS, d network.Discovery) (map[string]model.Document, model.Document) {
	metrics := map[string]model.Document{}
	for _, resource := range d.Resources {
		if resource["resource_type"] == "NAT_GATEWAY" {
			m, e := networkMetricSummary(ctx, archive, reader, d.Scope, resource)
			if e != nil {
				m = model.Document{"status": "UNAVAILABLE", "reason_code": "NATIVE_NAT_TELEMETRY_UNAVAILABLE", "missing_is_zero": false}
			}
			metrics[model.String(resource, "provider_resource_id")] = m
		}
	}
	prices := model.Document{"status": "UNAVAILABLE", "dimensions": []model.Document{}, "reason_code": "NATIVE_CUSTOMER_SKU_DIMENSIONS_UNAVAILABLE"}
	var skus []string
	e := a.Store.Do(ctx, d.Scope.TenantID, func(tx *store.Tx) error {
		var e error
		skus, e = service.CurrentNetworkSKUs(ctx, tx, d.Scope.AccountID, d.Scope.Region)
		return e
	})
	if e == nil && len(skus) > 0 {
		p, e := reader.NetworkPriceDimensions(ctx, d.Scope, skus)
		if e == nil {
			raw, _ := p["raw"].([]byte)
			ref, e := networkWire(ctx, archive, d.Scope.TenantID, "AWS_NETWORK_PRICE_DIMENSIONS", raw)
			if e == nil {
				delete(p, "raw")
				p["source_ref"] = ref
				p["status"] = "OBSERVED"
				prices = p
			}
		}
	}
	return metrics, prices
}
func collectNetworkDiscovery(ctx context.Context, a *Activities, tenant string, archive *native.Storage) error {
	if os.Getenv("NETWORK_READONLY_ENABLED") != "true" || a.Config.Fixture {
		return nil
	}
	var accounts []model.Document
	if e := a.Store.Do(ctx, tenant, func(tx *store.Tx) error { var e error; accounts, e = tx.List(ctx, "cloud_accounts"); return e }); e != nil {
		return e
	}
	var first error
	for _, account := range accounts {
		last, _ := time.Parse(time.RFC3339Nano, model.String(account, "network_last_discovered_at"))
		if !last.IsZero() && time.Since(last) < 10*time.Minute {
			continue
		}
		id, region := model.String(account, "account_id"), model.String(account, "region")
		if !strings.Contains(a.Config.AWSReadRole, ":"+id+":") {
			continue
		}
		scope := network.Scope{TenantID: tenant, AccountID: id, Region: region}
		if network.ValidateScope(scope) != nil {
			continue
		}
		reader, e := provider.NewAWS(ctx, region, a.Config.AWSReadRole, a.Config.AWSExternalID)
		if e != nil {
			if first == nil {
				first = e
			}
			continue
		}
		readCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		discovery, e := reader.NetworkDiscover(readCtx, scope)
		if e != nil {
			cancel()
			if first == nil {
				first = e
			}
			continue
		}
		metrics := map[string]model.Document{}
		for _, d := range discovery.Resources {
			if d["resource_type"] == "NAT_GATEWAY" {
				m, e := networkMetricSummary(readCtx, archive, reader, scope, d)
				if e != nil {
					m = model.Document{"status": "UNAVAILABLE", "reason_code": "NATIVE_NAT_TELEMETRY_UNAVAILABLE", "missing_is_zero": false}
				}
				metrics[model.String(d, "provider_resource_id")] = m
			}
		}
		prices := model.Document{"status": "UNAVAILABLE", "dimensions": []model.Document{}, "reason_code": "NATIVE_CUSTOMER_SKU_DIMENSIONS_UNAVAILABLE"}
		var skus []string
		e = a.Store.Do(ctx, tenant, func(tx *store.Tx) error {
			var e error
			skus, e = service.CurrentNetworkSKUs(ctx, tx, id, region)
			return e
		})
		if e == nil && len(skus) > 0 {
			p, e := reader.NetworkPriceDimensions(readCtx, scope, skus)
			if e == nil {
				raw, _ := p["raw"].([]byte)
				ref, e := networkWire(readCtx, archive, tenant, "AWS_NETWORK_PRICE_DIMENSIONS", raw)
				if e == nil {
					delete(p, "raw")
					p["source_ref"] = ref
					p["status"] = "OBSERVED"
					prices = p
				}
			}
		}
		cancel()
		e = PublishNetworkDiscovery(ctx, a.Store, archive, discovery, model.String(account, "id"), metrics, prices)
		if e != nil {
			if first == nil {
				first = e
			}
			continue
		}
		if e = a.Store.Do(ctx, tenant, func(tx *store.Tx) error {
			current, e := tx.Get(ctx, "cloud_accounts", model.String(account, "id"))
			if e != nil {
				return e
			}
			current["network_last_discovered_at"] = model.Now()
			_, e = tx.Update(ctx, "cloud_accounts", model.String(current, "id"), model.Number(current, "version"), current)
			return e
		}); e != nil && first == nil {
			first = e
		}
	}
	return first
}

type networkCheckpoint struct {
	a *Activities
	r network.Registration
}

func (c networkCheckpoint) Load(ctx context.Context, tenant, id string) (model.Document, error) {
	if tenant != c.r.TenantID {
		return nil, network.ErrEvidence
	}
	var out model.Document
	e := c.a.Store.Do(ctx, tenant, func(tx *store.Tx) error {
		var e error
		out, e = tx.SourceCheckpointGet(ctx, c.r.ID, "generation-"+id)
		if e == pgx.ErrNoRows {
			return nil
		}
		return e
	})
	return out, e
}
func (c networkCheckpoint) Save(ctx context.Context, tenant, id string, d model.Document) error {
	if tenant != c.r.TenantID {
		return network.ErrEvidence
	}
	return c.a.Store.Do(ctx, tenant, func(tx *store.Tx) error { return tx.SourceCheckpointSet(ctx, c.r.ID, "generation-"+id, d) })
}

// PublishNetworkGeneration requires the entire selected generation read back
// from analytics. It preserves native whole-account topology and limits source
// scope to the exact commissioned VPC/subnet/interface before issuing receipts.
func PublishNetworkGeneration(ctx context.Context, a *Activities, r network.Registration, g network.Generation, archive *native.Storage) error {
	if !g.Complete || g.Scope != (network.Scope{TenantID: r.TenantID, AccountID: r.AccountID, Region: r.Region}) || g.SourceID != r.ID || g.SourceVersion != r.Version {
		return errors.New("NETWORK_GENERATION_SCOPE_MISMATCH")
	}
	if e := archive.ValidateNetworkGeneration(ctx, g.Scope, g.ID, g.Rows); e != nil {
		return e
	}
	receiptID, revisionID := "network-receipt-"+g.ID, "network-revision-"+g.ID
	var resources []model.Document
	if e := a.Store.Do(ctx, r.TenantID, func(tx *store.Tx) error { var e error; resources, e = tx.List(ctx, "resources"); return e }); e != nil {
		return e
	}
	pending := []struct {
		resource  model.Document
		canonical model.Document
		ref       model.Document
	}{}
	for _, resource := range resources {
		kind := model.String(resource, "resource_type")
		if resource["provider"] != "AWS" || resource["account_id"] != r.AccountID || resource["region"] != r.Region || (kind != "NAT_GATEWAY" && kind != "ELASTIC_IP" && kind != "VPC") {
			continue
		}
		var prior model.Document
		e := a.Store.Do(ctx, r.TenantID, func(tx *store.Tx) error {
			var e error
			prior, e = tx.NetworkEvidenceLatestForConfig(ctx, model.String(resource, "id"), service.NetworkConfigurationHash(resource))
			return e
		})
		if e == pgx.ErrNoRows {
			continue
		}
		if e != nil {
			return e
		}
		raw, e := archive.Read(ctx, r.TenantID, networkDoc(prior["archive"]))
		if e != nil {
			return e
		}
		canonical, e := decodeNetworkSnapshot(raw, model.String(prior, "content_hash"), service.NetworkConfigurationHash(resource))
		if e != nil {
			return e
		}
		// Native collection can cover a VPC, subnet, or interface. Do not promote
		// a prefix/ENI source to complete account/network coverage.
		configuration := networkDoc(resource["network_configuration"])
		matches := false
		for _, scope := range r.ResourceIDs {
			if scope == model.String(configuration, "vpc_id") || scope == model.String(configuration, "subnet_id") || scope == model.String(resource, "provider_resource_id") {
				matches = true
			}
			for _, address := range networkRows(configuration["addresses"]) {
				if scope == model.String(address, "network_interface_id") {
					matches = true
				}
			}
		}
		if !matches {
			continue
		}
		canonical["flows"] = model.Document{"generation_id": g.ID, "population_hash": g.PopulationHash, "complete": g.Complete, "coverage": g.Coverage, "cohorts": g.Cohorts}
		canonical["source_id"], canonical["source_version"], canonical["source_registration_version"] = r.ID, g.ID, r.Version
		canonical["source_refs"] = append(networkRows(canonical["source_refs"]), model.Document{"kind": network.FlowKind, "id": receiptID, "version": g.ID, "sha256": g.PopulationHash})
		canonical["source_bindings"] = []model.Document{{"source_id": r.ID, "version": r.Version, "receipt_id": receiptID}}
		ref, e := networkArchive(ctx, archive, r.TenantID, "network-flow-evaluation", canonical)
		if e != nil {
			return e
		}
		pending = append(pending, struct {
			resource  model.Document
			canonical model.Document
			ref       model.Document
		}{resource, canonical, ref})
	}
	if len(pending) == 0 {
		return errors.New("NETWORK_REGISTERED_SCOPE_NOT_DISCOVERED")
	}
	generationRef, e := networkArchive(ctx, archive, r.TenantID, "network-flow-generation", g)
	if e != nil {
		return e
	}
	return a.Store.Do(ctx, r.TenantID, func(tx *store.Tx) error {
		current, e := tx.SourceGet(ctx, r.ID)
		if e != nil {
			return e
		}
		parsed, e := network.ParseRegistration(current)
		if e != nil || !parsed.Enabled || model.Bool(current, "revoked") || network.Hash(parsed) != network.Hash(r) {
			return errors.New("NETWORK_SOURCE_REGISTRATION_CHANGED")
		}
		if _, e = tx.SourceReceiptGet(ctx, receiptID); e == nil {
			return nil
		} else if e != pgx.ErrNoRows {
			return e
		}
		if _, e = tx.SourceRevisionCreate(ctx, model.Document{"id": revisionID, "source_id": r.ID, "revision_hash": g.ID, "kind": r.Kind, "config_hash": network.Hash(r), "source_version": g.ID, "source_refs": g.SourceRefs, "generation_id": g.ID}); e != nil {
			return e
		}
		if _, e = tx.SourceReceiptCreate(ctx, model.Document{"id": receiptID, "source_id": r.ID, "revision_id": revisionID, "kind": r.Kind, "config_hash": network.Hash(r), "registration_version": r.Version, "generation_id": g.ID, "source_version": g.ID, "complete": true, "complete_traffic_census": false, "source_refs": g.SourceRefs, "snapshot_archive": generationRef}); e != nil {
			return e
		}
		for _, p := range pending {
			resource, e := tx.Get(ctx, "resources", model.String(p.resource, "id"))
			if e != nil {
				return e
			}
			if service.NetworkConfigurationHash(resource) != p.canonical["config_hash"] {
				return errors.New("NETWORK_TOPOLOGY_CHANGED_DURING_FLOW_PUBLICATION")
			}
			if _, e = tx.NetworkEvidenceCreate(ctx, model.String(resource, "id"), r.ID, p.canonical, p.ref); e != nil {
				return e
			}
		}
		if e = tx.Audit(ctx, "network-ingester", "network.evidence.published", g.ID, model.Document{"source_id": r.ID, "row_count": g.Rows, "complete_traffic_census": false, "execution_authorized": false}); e != nil {
			return e
		}
		return tx.Event(ctx, "network.evidence.published", model.Document{"source_id": r.ID, "generation_id": g.ID, "execution_authorized": false})
	})
}
func SyncNetworkSource(ctx context.Context, a *Activities, r network.Registration, factory func(context.Context, network.Registration) (*provider.AWS, error), archive *native.Storage) (err error) {
	conn, e := a.Store.Pool.Acquire(ctx)
	if e != nil {
		return e
	}
	defer conn.Release()
	lock := "network-source:" + r.TenantID + ":" + r.ID
	var held bool
	if e = conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1,0))", lock).Scan(&held); e != nil || !held {
		return e
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = conn.Exec(cleanup, "SELECT pg_advisory_unlock(hashtextextended($1,0))", lock)
	}()
	status := model.Document{"status": "SYNCING", "reason_code": "NETWORK_NATIVE_SOURCE_SYNC_IN_PROGRESS", "last_sync_version": r.Version, "config_hash": network.Hash(r), "last_sync_at": model.Now()}
	save := func() error {
		return a.Store.Do(ctx, r.TenantID, func(tx *store.Tx) error { return tx.SourceCheckpointSet(ctx, r.ID, "status", status) })
	}
	if e = save(); e != nil {
		return e
	}
	defer func() {
		if err != nil {
			status["status"], status["reason_code"] = "BLOCKED", "NETWORK_SOURCE_EVIDENCE_UNAVAILABLE"
		}
		status["last_sync_at"] = model.Now()
		if e := save(); err == nil {
			err = e
		}
	}()
	reader, e := factory(ctx, r)
	if e != nil {
		return e
	}
	readCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	// A commissioned source is itself explicit opt-in to its exact read role.
	// It does not require unrelated globally configured discovery credentials.
	discovery, e := reader.NetworkDiscover(readCtx, network.Scope{TenantID: r.TenantID, AccountID: r.AccountID, Region: r.Region})
	if e != nil {
		return e
	}
	metrics, prices := readNetworkEvaluationInputs(readCtx, a, archive, reader, discovery)
	if e = PublishNetworkDiscovery(readCtx, a.Store, archive, discovery, "", metrics, prices); e != nil {
		return e
	}
	objects, e := reader.FlowObjects(readCtx, r)
	if e != nil {
		return e
	}
	generation, e := network.IngestFlow(readCtx, r, objects, reader, networkArchiveAdapter{archive}, archive, networkCheckpoint{a, r})
	if e != nil {
		return e
	}
	if e = PublishNetworkGeneration(ctx, a, r, generation, archive); e != nil {
		return e
	}
	status["status"], status["reason_code"] = "HEALTHY", "NATIVE_NETWORK_FLOW_GENERATION_PERSISTED"
	status["latest_revision_id"], status["latest_receipt_id"] = "network-revision-"+generation.ID, "network-receipt-"+generation.ID
	return nil
}
func networkTick(ctx context.Context, a *Activities, tenant string) error {
	if a.Config.Fixture {
		return nil
	}
	var registrations []model.Document
	if e := a.Store.Do(ctx, tenant, func(tx *store.Tx) error { var e error; registrations, e = tx.SourceList(ctx); return e }); e != nil {
		return e
	}
	enabled := os.Getenv("NETWORK_READONLY_ENABLED") == "true"
	for _, d := range registrations {
		if d["kind"] == network.FlowKind && model.Bool(d, "enabled") {
			enabled = true
		}
	}
	if !enabled {
		return nil
	}
	archive, e := native.StorageFromEnvironment(ctx, false)
	if e != nil {
		return e
	}
	first := collectNetworkDiscovery(ctx, a, tenant, archive)
	encoded := os.Getenv("AWS_NETWORK_READ_BINDINGS_JSON")
	if encoded == "" {
		encoded = os.Getenv("AWS_SOURCE_READ_BINDINGS_JSON")
	}
	factory, e := source.NetworkAWSFactory(encoded)
	if e != nil {
		return e
	}
	for _, d := range registrations {
		if d["kind"] != network.FlowKind || !model.Bool(d, "enabled") || model.Bool(d, "revoked") {
			continue
		}
		last, _ := time.Parse(time.RFC3339Nano, model.String(d, "last_sync_at"))
		if !last.IsZero() && time.Since(last) < time.Minute {
			continue
		}
		r, e := network.ParseRegistration(d)
		if e == nil {
			e = SyncNetworkSource(ctx, a, r, factory, archive)
		}
		if e != nil && first == nil {
			first = e
		}
	}
	return first
}
