package store

import (
	"context"

	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
)

// Key bindings are installed by an operator connection with no application
// INSERT/UPDATE privilege. The bootstrap never selects its own trust roots.
func (t *Tx) groupJournalCommissionedKeys(ctx context.Context, b FleetGroupJournalBootstrap) (FleetGroupJournalKeys, error) {
	var k FleetGroupJournalKeys
	err := t.QueryRow(ctx, `SELECT k.signer_key,k.pipeline_key,k.ledger_key FROM public.fleet_group_journal_key_bindings k JOIN public.fleet_fixture_proposals p ON p.tenant_id=k.tenant_id AND p.profile_id=k.profile_id AND p.profile_generation=k.profile_generation JOIN public.fleet_fixture_prepared_programs g ON g.tenant_id=p.tenant_id AND g.proposal_id=p.id WHERE k.tenant_id=$1 AND k.id=$2 AND g.id=$3 AND k.realm=$4::jsonb AND k.pipeline_id=$5`, t.Tenant, b.KeyBindingID, b.PreparedProgramID, groupJournalRealmBytes(b.Parent.Program.Realm), b.Parent.Program.ArtifactContext.PipelineID).Scan(&k.Signer, &k.Pipeline, &k.Ledger)
	return k, err
}
func groupJournalRealmBytes(r g.Realm) []byte { raw, _, _ := groupJournalBytes(r); return raw }

func (t *Tx) groupJournalForwardCurrent(ctx context.Context, b FleetGroupJournalBootstrap) error {
	var current bool
	if err := t.QueryRow(ctx, `SELECT public.fleet_group_prepared_current($1,$2)`, t.Tenant, b.PreparedProgramID).Scan(&current); err != nil {
		return err
	}
	if !current {
		return ErrGroupJournalInvalid
	}
	return nil
}
