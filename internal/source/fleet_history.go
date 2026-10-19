package source

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleethistory"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

// FleetHistoryPipeline captures one registered ASG without constructing an
// execution plan, inventing an inventory resource or requiring a candidate ASG.
// Only the ingestion identity may publish its observations. Neither an API
// request nor a historical query supplies authoritative membership or timestamps.
type FleetHistoryPipeline struct {
	Store         *store.Store
	ReaderFactory func(context.Context, Registration, string) (FleetReader, error)
	Archive       func(context.Context, string, string, []byte) (model.Document, error)
	Now           func() time.Time
}

func historyRegistration(d model.Document) (fleethistory.Registration, error) {
	return store.FleetHistoryRegistrationDocument(d)
}

// historyMembers proves typed membership against the complete native response.
// It deliberately does not apply execution eligibility filters: an unhealthy
// instance is still a member. Native V1 ASG responses do not establish EC2 launch
// time or hardware evidence, so those remain unknown rather than being inferred.
func historyMembers(r fleethistory.Registration, native provider.FleetInventoryEvidence, now time.Time) ([]fleethistory.Member, error) {
	if fleethistory.ValidateRegistration(r) != nil || native.SchemaVersion != "1" || native.Provider != "AWS" || native.AccountID != r.Binding.AccountID || native.Region != r.Binding.Region || native.CollectedAt.IsZero() || native.CollectedAt.Before(now.Add(-time.Minute)) || native.CollectedAt.After(now.Add(5*time.Second)) {
		return nil, errors.New("HISTORY_NATIVE_BINDING_OR_TIME_INVALID")
	}
	name := strings.SplitN(r.ASGARN, ":autoScalingGroupName/", 2)[1]
	groups, err := fleetRawGroups(native, []string{name})
	if err != nil {
		return nil, err
	}
	if len(groups) != 1 || groups[0].ARN != r.ASGARN || groups[0].Name != name || len(groups[0].Members) > 256 {
		return nil, errors.New("HISTORY_NATIVE_GROUP_INVALID")
	}
	members := make([]fleethistory.Member, 0, len(groups[0].Members))
	seen := map[string]bool{}
	for _, member := range groups[0].Members {
		version, err := strconv.ParseUint(member.LaunchTemplate.Version, 10, 64)
		if err != nil || version < 1 || !fleetTemplateID.MatchString(member.LaunchTemplate.ID) || !fleetInstanceID.MatchString(member.InstanceID) || seen[member.InstanceID] {
			return nil, errors.New("HISTORY_NATIVE_MEMBER_IDENTITY_UNAVAILABLE")
		}
		seen[member.InstanceID] = true
		members = append(members, fleethistory.Member{InstanceID: member.InstanceID, LaunchTemplateID: member.LaunchTemplate.ID, LaunchTemplateVersion: version})
	}
	sort.Slice(members, func(i, j int) bool { return members[i].InstanceID < members[j].InstanceID })
	return members, nil
}

func (p *FleetHistoryPipeline) Capture(ctx context.Context, tenant, registrationID string) (model.Document, error) {
	if p.Store == nil || p.ReaderFactory == nil || p.Archive == nil {
		return nil, errors.New("HISTORY_CAPTURE_DEPENDENCIES_REQUIRED")
	}
	var registered, source model.Document
	if err := p.Store.Do(ctx, tenant, func(tx *store.Tx) error {
		var err error
		registered, err = tx.FleetHistoryRegistrationGet(ctx, registrationID)
		if err != nil {
			return err
		}
		r, err := historyRegistration(registered)
		if err != nil {
			return err
		}
		source, err = tx.SourceGet(ctx, r.SourceID)
		return err
	}); err != nil {
		return nil, err
	}
	r, err := historyRegistration(registered)
	if err != nil || r.Binding.TenantID != tenant {
		return nil, errors.New("HISTORY_CAPTURE_REGISTRATION_BINDING_INVALID")
	}
	configuration, err := ParseRegistration(source)
	if err != nil || !configuration.Enabled || model.Bool(source, "revoked") || configuration.TenantID != tenant || configuration.Version < r.SourceRegistrationVersion || ConfigurationHash(source) != r.SourceConfigHash {
		return nil, errors.New("HISTORY_CAPTURE_SOURCE_UNAVAILABLE")
	}
	approved := configuration.PayerAccountID == r.Binding.AccountID
	for _, account := range configuration.UsageAccountIDs {
		approved = approved || account == r.Binding.AccountID
	}
	if !approved || configuration.Region != r.Binding.Region {
		return nil, errors.New("HISTORY_CAPTURE_ACCOUNT_NOT_REGISTERED")
	}
	reader, err := p.ReaderFactory(ctx, configuration, r.Binding.AccountID)
	if err != nil {
		return nil, err
	}
	name := strings.SplitN(r.ASGARN, ":autoScalingGroupName/", 2)[1]
	readContext, cancel := context.WithTimeout(ctx, 45*time.Second)
	native, err := reader.FleetInventory(readContext, r.Binding.Region, r.Binding.AccountID, []string{name})
	cancel()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if p.Now != nil {
		now = p.Now().UTC()
	}
	members, err := historyMembers(r, native, now)
	if err != nil {
		return nil, err
	}
	registrationHash := fleethistory.RegistrationHash(r)
	ref, err := p.Archive(ctx, tenant, "history-"+registrationHash, native.Raw)
	if err != nil {
		return nil, err
	}
	if model.String(ref, "bucket") == "" || !strings.HasPrefix(model.String(ref, "key"), "tenant/"+tenant+"/fleet/") || strings.ContainsAny(model.String(ref, "key"), "\\\r\n\x00") || strings.Contains(model.String(ref, "key"), "..") || model.String(ref, "version_id") == "" || model.String(ref, "version_id") == "null" || model.String(ref, "body_sha256") != native.RawSHA256 {
		return nil, errors.New("HISTORY_VERSIONED_RAW_ARCHIVE_REQUIRED")
	}
	revisionHash := Hash(model.Document{"kind": "AWS_FLEET_MEMBERSHIP", "source_id": r.SourceID, "registration_version": configuration.Version, "config_hash": r.SourceConfigHash, "history_registration_hash": registrationHash, "raw_sha256": native.RawSHA256})
	revisionID := "fleet-history-rev-" + revisionHash
	receiptID := "fleet-history-" + Hash(model.Document{"revision_id": revisionID, "collected_at": native.CollectedAt.UTC()})
	document := model.Document{"id": receiptID, "kind": "AWS_FLEET_MEMBERSHIP", "source_id": r.SourceID, "revision_id": revisionID, "position": "HISTORY_CAPTURE", "binding": Object(r.Binding), "history_registration_id": r.ID, "history_registration_version": r.Version, "history_registration_hash": registrationHash, "groups": native.Groups, "collected_at": native.CollectedAt.UTC(), "raw_object": ref, "registration_version": configuration.Version, "read_role_binding_id": configuration.ReadRoleBindingID, "config_hash": r.SourceConfigHash, "status": "OBSERVED_ONLY", "execution_authorized": false}
	raw, _ := json.Marshal(document)
	if len(raw) > 128<<10 {
		return nil, errors.New("HISTORY_NATIVE_METADATA_LIMIT")
	}
	var result model.Document
	err = p.Store.Do(ctx, tenant, func(tx *store.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT fleet_history_lock($1,$2)", tenant, r.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "SELECT fleet_history_source_lock($1,$2)", tenant, r.SourceID); err != nil {
			return err
		}
		current, err := tx.SourceGet(ctx, r.SourceID)
		if err != nil {
			return err
		}
		currentRegistration, err := tx.FleetHistoryRegistrationGet(ctx, r.ID)
		if err != nil {
			return err
		}
		currentTyped, err := historyRegistration(currentRegistration)
		if err != nil || fleethistory.RegistrationHash(currentTyped) != registrationHash || !model.Bool(current, "enabled") || model.Bool(current, "revoked") || model.Number(current, "version") != configuration.Version || ConfigurationHash(current) != r.SourceConfigHash {
			return errors.New("HISTORY_SOURCE_OR_REGISTRATION_CHANGED_DURING_CAPTURE")
		}
		if _, err := tx.SourceRevisionGet(ctx, revisionID); err == pgx.ErrNoRows {
			if _, err = tx.SourceRevisionCreate(ctx, model.Document{"id": revisionID, "source_id": r.SourceID, "kind": "AWS_FLEET_MEMBERSHIP", "registration_version": configuration.Version, "revision_hash": revisionHash, "config_hash": r.SourceConfigHash, "history_registration_hash": registrationHash, "raw_object": ref, "observed_at": native.CollectedAt.UTC()}); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		receipt, err := tx.SourceReceiptGet(ctx, receiptID)
		if err == pgx.ErrNoRows {
			if _, err = tx.SourceReceiptCreate(ctx, document); err != nil {
				return err
			}
			receipt, err = tx.SourceReceiptGet(ctx, receiptID)
		}
		if err != nil {
			return err
		}
		provenance, err := tx.FleetHistorySourceReference(ctx, receiptID, "AWS_FLEET_MEMBERSHIP", r.ASGARN)
		if err != nil {
			return err
		}
		receivedAt, err := time.Parse(time.RFC3339Nano, model.String(receipt, "created_at"))
		if err != nil {
			return errors.New("HISTORY_NATIVE_RECEIPT_TIME_INVALID")
		}
		observation := fleethistory.MembershipObservation{SchemaVersion: fleethistory.SchemaVersion, ID: "history-observation-" + Hash(model.Document{"registration_hash": registrationHash, "receipt_id": receiptID}), RegistrationID: r.ID, RegistrationVersion: r.Version, RegistrationHash: registrationHash, ASGARN: r.ASGARN, ObservedAt: native.CollectedAt.UTC(), ReceivedAt: receivedAt, Source: provenance, Members: members}
		result, _, err = tx.FleetHistoryObservationAppend(ctx, observation)
		return err
	})
	return result, err
}
