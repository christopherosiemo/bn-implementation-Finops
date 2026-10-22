package provider

import (
	"context"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var ebsVolumeID = regexp.MustCompile(`^vol-[0-9a-f]{8}([0-9a-f]{9})?$`)
var ebsSnapshotID = regexp.MustCompile(`^snap-[0-9a-f]{8}([0-9a-f]{9})?$`)
var ebsInstanceID = regexp.MustCompile(`^i-[0-9a-f]{8}([0-9a-f]{9})?$`)

func ebsFields(n *rdsNode, s, b, i map[string]string) (model.Document, error) {
	if n == nil {
		return nil, ErrEBSRead
	}
	d, e := rdsFields(n, s, b, i)
	if e != nil {
		return nil, ErrEBSRead
	}
	return d, nil
}
func ebsTags(n *rdsNode) (any, error) {
	if n.get("tagSet") == nil {
		return nil, nil
	}
	out := []model.Document{}
	seen := map[string]bool{}
	for _, x := range n.list("tagSet") {
		key := x.value("key")
		if key == "" || seen[key] {
			return nil, ErrEBSRead
		}
		seen[key] = true
		out = append(out, model.Document{"key": key, "value": x.value("value")})
	}
	sort.Slice(out, func(i, j int) bool { return model.String(out[i], "key") < model.String(out[j], "key") })
	return out, nil
}
func ebsAttachments(n *rdsNode) (any, error) {
	if n.get("attachmentSet") == nil {
		return nil, nil
	}
	out := []model.Document{}
	seen := map[string]bool{}
	for _, x := range n.list("attachmentSet") {
		d, e := ebsFields(x, map[string]string{"volume_id": "volumeId", "instance_id": "instanceId", "device": "device", "state": "status", "attach_time": "attachTime", "associated_resource": "associatedResource", "instance_owning_service": "instanceOwningService"}, map[string]string{"delete_on_termination": "deleteOnTermination"}, nil)
		if e != nil || !ebsInstanceID.MatchString(model.String(d, "instance_id")) && model.String(d, "associated_resource") == "" {
			return nil, ErrEBSRead
		}
		key := model.String(d, "instance_id") + "/" + model.String(d, "device")
		if seen[key] {
			return nil, ErrEBSRead
		}
		seen[key] = true
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		return model.String(out[i], "instance_id")+model.String(out[i], "device") < model.String(out[j], "instance_id")+model.String(out[j], "device")
	})
	return out, nil
}
func ebsVolume(n *rdsNode, s EBSScope, hash string) (model.Document, error) {
	d, e := ebsFields(n, map[string]string{"volume_id": "volumeId", "availability_zone": "availabilityZone", "state": "status", "volume_type": "volumeType", "kms_key_id": "kmsKeyId", "create_time": "createTime", "snapshot_id": "snapshotId", "outpost_arn": "outpostArn", "sse_type": "sseType", "volume_initialization_rate": "volumeInitializationRate"}, map[string]string{"encrypted": "encrypted", "multi_attach_enabled": "multiAttachEnabled", "fast_restored": "fastRestored"}, map[string]string{"size_gib": "size", "iops": "iops", "throughput_mibps": "throughput"})
	if e != nil || !ebsVolumeID.MatchString(model.String(d, "volume_id")) || model.String(d, "availability_zone") == "" || !strings.HasPrefix(model.String(d, "availability_zone"), s.Region) {
		return nil, ErrEBSRead
	}
	d["operator"] = nil
	if n.get("operator") != nil {
		operator, e := ebsFields(n.get("operator"), map[string]string{"principal": "principal"}, map[string]string{"managed": "managed"}, nil)
		if e != nil {
			return nil, e
		}
		d["operator"] = operator
	}
	d["provider_resource_id"] = d["volume_id"]
	d["resource_type"] = "EBS_VOLUME"
	d["provider"] = "AWS"
	d["account_id"] = s.AccountID
	d["region"] = s.Region
	d["raw_page_sha256"] = hash
	d["attachments"], e = ebsAttachments(n)
	if e != nil {
		return nil, e
	}
	d["tags"], e = ebsTags(n)
	return d, e
}
func ebsSnapshot(n *rdsNode, s EBSScope, hash string) (model.Document, error) {
	d, e := ebsFields(n, map[string]string{"snapshot_id": "snapshotId", "volume_id": "volumeId", "owner_id": "ownerId", "state": "status", "start_time": "startTime", "completion_time": "completionTime", "description": "description", "progress": "progress", "kms_key_id": "kmsKeyId", "storage_tier": "storageTier", "restore_expiry_time": "restoreExpiryTime", "sse_type": "sseType"}, map[string]string{"encrypted": "encrypted"}, map[string]string{"size_gib": "volumeSize", "full_snapshot_size_bytes": "fullSnapshotSizeInBytes"})
	if e != nil || !ebsSnapshotID.MatchString(model.String(d, "snapshot_id")) || model.String(d, "owner_id") != s.AccountID {
		return nil, ErrEBSRead
	}
	d["provider_resource_id"] = d["snapshot_id"]
	d["resource_type"] = "EBS_SNAPSHOT"
	d["provider"] = "AWS"
	d["account_id"] = s.AccountID
	d["region"] = s.Region
	d["raw_page_sha256"] = hash
	d["tags"], e = ebsTags(n)
	return d, e
}
func ebsNative(n *rdsNode, s EBSScope, hash string) (model.Document, error) {
	d := model.Document{"native": rdsNormalizedNode(n), "raw_page_sha256": hash, "account_id": s.AccountID, "region": s.Region}
	for key, tag := range map[string]string{"volume_id": "volumeId", "snapshot_id": "snapshotId", "image_id": "imageId", "owner_id": "ownerId", "state": "state", "availability_zone": "availabilityZone", "modification_state": "modificationState", "start_time": "startTime", "end_time": "endTime", "lock_state": "lockState", "storage_tier": "storageTier", "restore_expiry_time": "restoreExpiryTime"} {
		if n.get(tag) != nil {
			d[key] = n.value(tag)
		}
	}
	if owner := model.String(d, "owner_id"); owner != "" && owner != s.AccountID {
		return nil, ErrEBSRead
	}
	return d, nil
}
func ebsImage(n *rdsNode, s EBSScope, hash string) (model.Document, error) {
	d, e := ebsNative(n, s, hash)
	if e != nil || !strings.HasPrefix(n.value("imageId"), "ami-") || n.value("imageOwnerId") != s.AccountID {
		return nil, ErrEBSRead
	}
	d["image_id"] = n.value("imageId")
	d["owner_id"] = n.value("imageOwnerId")
	d["name"] = n.value("name")
	d["state"] = n.value("imageState")
	var refs any
	if n.get("blockDeviceMapping") != nil {
		rows := []model.Document{}
		for _, x := range n.list("blockDeviceMapping") {
			m := model.Document{"device_name": x.value("deviceName"), "snapshot_id": nil}
			if b := x.get("ebs"); b != nil {
				m["snapshot_id"] = b.value("snapshotId")
			}
			rows = append(rows, m)
		}
		refs = rows
	}
	d["block_device_mappings"] = refs
	return d, nil
}

type ebsParser func(*rdsNode, EBSScope, string) (model.Document, error)

func (r *ebsRead) pages(ctx context.Context, action, collection string, values url.Values, parse ebsParser) ([]model.Document, error) {
	out := []model.Document{}
	seen := map[string]bool{}
	token := ""
	for page := 0; page < 128; page++ {
		v := url.Values{}
		for k, x := range values {
			v[k] = append([]string{}, x...)
		}
		if action != "DescribeSnapshotAttribute" && !(action == "DescribeInstances" && len(v) > 0) {
			v.Set("MaxResults", "100")
		}
		if token != "" {
			v.Set("NextToken", token)
		}
		raw, e := r.query(ctx, "ec2", action, v)
		if e != nil {
			return nil, e
		}
		tree, e := ebsTree(raw, action)
		if e != nil || tree.get(collection) == nil {
			return nil, ErrEBSRead
		}
		for _, n := range tree.list(collection) {
			d, e := parse(n, r.scope, rdsSHA(raw))
			if e != nil {
				return nil, e
			}
			out = append(out, d)
			if len(out) > 4096 {
				return nil, ErrEBSRead
			}
		}
		token = tree.value("nextToken")
		if token == "" {
			return out, nil
		}
		if len(token) > 8192 || seen[token] {
			return nil, ErrEBSRead
		}
		seen[token] = true
	}
	return nil, ErrEBSRead
}
func ebsUnique(rows []model.Document, key string) error {
	seen := map[string]bool{}
	for _, d := range rows {
		id := model.String(d, key)
		if id == "" || seen[id] {
			return ErrEBSRead
		}
		seen[id] = true
	}
	return nil
}
func ebsDocuments(v any) []model.Document {
	if rows, ok := v.([]model.Document); ok {
		return rows
	}
	out := []model.Document{}
	if rows, ok := v.([]any); ok {
		for _, row := range rows {
			switch x := row.(type) {
			case model.Document:
				out = append(out, x)
			case map[string]any:
				out = append(out, model.Document(x))
			}
		}
	}
	return out
}
func (r *ebsRead) attachments(ctx context.Context, volumes []model.Document) ([]model.Document, []model.Document, error) {
	ids := map[string]bool{}
	for _, v := range volumes {
		for _, a := range ebsDocuments(v["attachments"]) {
			if id := model.String(a, "instance_id"); id != "" {
				ids[id] = true
			}
		}
	}
	ordered := []string{}
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	instances := []model.Document{}
	types := map[string]bool{}
	for first := 0; first < len(ordered); first += 100 {
		last := min(first+100, len(ordered))
		v := url.Values{}
		for i, id := range ordered[first:last] {
			v.Set("InstanceId."+strconv.Itoa(i+1), id)
		}
		rows, e := r.pages(ctx, "DescribeInstances", "reservationSet", v, func(n *rdsNode, s EBSScope, h string) (model.Document, error) {
			if n.value("ownerId") != s.AccountID {
				return nil, ErrEBSRead
			}
			return model.Document{"reservation": n, "hash": h}, nil
		})
		if e != nil {
			return nil, nil, e
		}
		for _, reservation := range rows {
			n := reservation["reservation"].(*rdsNode)
			if n.get("instancesSet") == nil {
				return nil, nil, ErrEBSRead
			}
			for _, x := range n.list("instancesSet") {
				id := x.value("instanceId")
				if !ids[id] {
					return nil, nil, ErrEBSRead
				}
				d, e := ebsFields(x, map[string]string{"instance_id": "instanceId", "instance_type": "instanceType", "root_device_name": "rootDeviceName", "root_device_type": "rootDeviceType", "virtualization_type": "virtualizationType", "launch_time": "launchTime", "image_id": "imageId"}, map[string]string{"ebs_optimized": "ebsOptimized"}, nil)
				if e != nil {
					return nil, nil, e
				}
				d["account_id"] = sAccount(r.scope)
				d["region"] = r.scope.Region
				d["raw_page_sha256"] = reservation["hash"]
				if x.get("instanceState") != nil {
					d["state"] = x.get("instanceState").value("name")
				}
				if x.get("placement") != nil {
					d["availability_zone"] = x.get("placement").value("availabilityZone")
				}
				d["monitoring_state"] = nil
				if x.get("monitoring") != nil {
					d["monitoring_state"] = x.get("monitoring").value("state")
				}
				d["block_device_mappings"] = nil
				if x.get("blockDeviceMapping") != nil {
					maps := []model.Document{}
					for _, m := range x.list("blockDeviceMapping") {
						b := m.get("ebs")
						if b == nil {
							continue
						}
						row, e := ebsFields(b, map[string]string{"volume_id": "volumeId", "state": "status", "attach_time": "attachTime"}, map[string]string{"delete_on_termination": "deleteOnTermination"}, nil)
						if e != nil {
							return nil, nil, e
						}
						row["device_name"] = m.value("deviceName")
						maps = append(maps, row)
					}
					d["block_device_mappings"] = maps
				}
				types[model.String(d, "instance_type")] = true
				instances = append(instances, d)
			}
		}
	}
	if ebsUnique(instances, "instance_id") != nil || len(instances) != len(ordered) {
		return nil, nil, ErrEBSRead
	}
	names := []string{}
	for name := range types {
		if !rdsPart.MatchString(name) {
			return nil, nil, ErrEBSRead
		}
		names = append(names, name)
	}
	sort.Strings(names)
	catalog := []model.Document{}
	for first := 0; first < len(names); first += 100 {
		v := url.Values{}
		for i, name := range names[first:min(first+100, len(names))] {
			v.Set("InstanceType."+strconv.Itoa(i+1), name)
		}
		rows, e := r.pages(ctx, "DescribeInstanceTypes", "instanceTypeSet", v, ebsInstanceType)
		if e != nil {
			return nil, nil, e
		}
		catalog = append(catalog, rows...)
	}
	if ebsUnique(catalog, "instance_type") != nil || len(catalog) != len(names) {
		return nil, nil, ErrEBSRead
	}
	for _, c := range catalog {
		if !types[model.String(c, "instance_type")] {
			return nil, nil, ErrEBSRead
		}
	}
	sort.Slice(instances, func(i, j int) bool {
		return model.String(instances[i], "instance_id") < model.String(instances[j], "instance_id")
	})
	return instances, catalog, nil
}
func sAccount(s EBSScope) string { return s.AccountID }
func ebsInstanceType(n *rdsNode, s EBSScope, h string) (model.Document, error) {
	d, e := ebsFields(n, map[string]string{"instance_type": "instanceType", "hypervisor": "hypervisor"}, map[string]string{"current_generation": "currentGeneration", "bare_metal": "bareMetal"}, nil)
	if e != nil || !rdsPart.MatchString(model.String(d, "instance_type")) {
		return nil, ErrEBSRead
	}
	d["ebs"] = nil
	d["raw_page_sha256"] = h
	if b := n.get("ebsInfo"); b != nil {
		info, e := ebsFields(b, map[string]string{"optimized_support": "ebsOptimizedSupport", "encryption_support": "encryptionSupport", "nvme_support": "nvmeSupport"}, nil, nil)
		if e != nil {
			return nil, e
		}
		info["optimized_info"] = nil
		if o := b.get("ebsOptimizedInfo"); o != nil {
			caps := model.Document{}
			for key, tag := range map[string]string{"baseline_bandwidth_mbps": "baselineBandwidthInMbps", "baseline_throughput_mb_per_second": "baselineThroughputInMBps", "baseline_iops": "baselineIops", "maximum_bandwidth_mbps": "maximumBandwidthInMbps", "maximum_throughput_mb_per_second": "maximumThroughputInMBps", "maximum_iops": "maximumIops"} {
				caps[key] = nil
				if o.get(tag) != nil {
					value := o.value(tag)
					if !metricNumber.MatchString(value) {
						return nil, ErrEBSRead
					}
					caps[key] = value
				}
			}
			info["optimized_info"] = caps
		}
		d["ebs"] = info
	}
	return d, nil
}

func (a *AWS) EBSDiscover(ctx context.Context, s EBSScope) (EBSSnapshot, error) {
	out := EBSSnapshot{Coverage: []model.Document{}}
	r, e := newEBSRead(a, s)
	if e != nil {
		return out, e
	}
	out.Volumes, e = r.pages(ctx, "DescribeVolumes", "volumeSet", url.Values{"IncludeManagedResources": {"true"}}, ebsVolume)
	if e != nil || ebsUnique(out.Volumes, "volume_id") != nil {
		return EBSSnapshot{}, ErrEBSRead
	}
	collect := func(component, action, collection, key string, v url.Values, parse ebsParser, target *[]model.Document) {
		rows, err := r.pages(ctx, action, collection, v, parse)
		status := "OBSERVED_COMPLETE_ACCOUNT_REGION_POINT_READ"
		if err != nil || key != "" && ebsUnique(rows, key) != nil {
			status = "UNAVAILABLE"
			rows = nil
		}
		*target = rows
		out.Coverage = append(out.Coverage, model.Document{"component": component, "action": action, "status": status, "missing_is_empty": false})
	}
	collect("snapshots", "DescribeSnapshots", "snapshotSet", "snapshot_id", url.Values{"Owner.1": {"self"}}, ebsSnapshot, &out.Snapshots)
	collect("owned_images", "DescribeImages", "imagesSet", "image_id", url.Values{"Owner.1": {"self"}, "IncludeDeprecated": {"true"}, "IncludeDisabled": {"true"}}, ebsImage, &out.OwnedImages)
	collect("fast_snapshot_restores", "DescribeFastSnapshotRestores", "fastSnapshotRestoreSet", "", url.Values{"Filter.1.Name": {"owner-id"}, "Filter.1.Value.1": {s.AccountID}}, ebsNative, &out.FastSnapshotRestores)
	collect("snapshot_tiers", "DescribeSnapshotTierStatus", "snapshotTierStatusSet", "", url.Values{}, ebsNative, &out.SnapshotTierStatuses)
	collect("snapshot_locks", "DescribeLockedSnapshots", "snapshotSet", "", url.Values{}, ebsNative, &out.LockedSnapshots)
	collect("volume_modifications", "DescribeVolumesModifications", "volumeModificationSet", "volume_id", url.Values{}, ebsNative, &out.VolumeModifications)
	collect("volume_statuses", "DescribeVolumeStatus", "volumeStatusSet", "volume_id", url.Values{"IncludeAllVolumes": {"true"}}, ebsNative, &out.VolumeStatuses)
	out.Instances, out.InstanceTypes, e = r.attachments(ctx, out.Volumes)
	if e != nil {
		out.Instances = nil
		out.InstanceTypes = nil
		out.Coverage = append(out.Coverage, model.Document{"component": "attachment_instance_capabilities", "status": "UNAVAILABLE"})
	} else {
		out.Coverage = append(out.Coverage, model.Document{"component": "attachment_instance_capabilities", "status": "OBSERVED_EXACT_ATTACHED_INSTANCE_TYPES"})
	}
	if out.Snapshots != nil && len(out.Snapshots) <= 256 {
		out.SnapshotPermissions = []model.Document{}
		for _, snapshot := range out.Snapshots {
			id := model.String(snapshot, "snapshot_id")
			raw, err := r.query(ctx, "ec2", "DescribeSnapshotAttribute", url.Values{"SnapshotId": {id}, "Attribute": {"createVolumePermission"}})
			if err != nil {
				out.Coverage = append(out.Coverage, model.Document{"component": "snapshot_permissions", "snapshot_id": id, "status": "UNAVAILABLE"})
				continue
			}
			n, err := ebsTree(raw, "DescribeSnapshotAttribute")
			if err != nil || n.value("snapshotId") != id || n.get("createVolumePermission") == nil {
				return EBSSnapshot{}, ErrEBSRead
			}
			d := model.Document{"snapshot_id": id, "permissions": rdsNormalizedNode(n.get("createVolumePermission")), "raw_page_sha256": rdsSHA(raw)}
			out.SnapshotPermissions = append(out.SnapshotPermissions, d)
			out.Coverage = append(out.Coverage, model.Document{"component": "snapshot_permissions", "snapshot_id": id, "status": "OBSERVED"})
		}
	} else {
		out.Coverage = append(out.Coverage, model.Document{"component": "snapshot_permissions", "status": "UNAVAILABLE_SCOPE_BOUND_OR_SNAPSHOT_READ"})
	}
	out.Coverage = append(out.Coverage, model.Document{"component": "external_backup_retention_iac_dependencies", "status": "UNKNOWN_REQUIRES_INDEPENDENT_AUTHORITY"}, model.Document{"component": "modifications_rolling_24h_count", "status": "UNKNOWN_LATEST_MODIFICATION_IS_NOT_COMPLETE_HISTORY"})
	out.EBSReadEvidence = r.evidence()
	return out, nil
}
