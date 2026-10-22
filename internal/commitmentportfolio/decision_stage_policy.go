package commitmentportfolio

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetdecision"
	"github.com/jackc/pgx/v5"
)

const DecisionStagePolicyPurpose = "CUSTOMER_WORKLOAD_OPTIMIZATION_CONSTRAINT"
const DecisionStagePolicyBasis = "CUSTOMER_APPROVED_SIZE_ALLOWLIST_AND_CONFIGURATION_CONTROLLER_SCOPE"

// An operator-installed customer constraint, never an observed native catalog
// or a public API input. Customer approval authorizes this bounded analytical
// scope, not a purchase, configuration change, or assertion about all AWS.
type DecisionStagePolicy struct {
	SchemaVersion           string                         `json:"schema_version"`
	ID                      string                         `json:"id"`
	Revision                int64                          `json:"revision"`
	Purpose                 string                         `json:"purpose"`
	Basis                   string                         `json:"basis"`
	TenantID                string                         `json:"tenant_id"`
	WorkloadID              string                         `json:"workload_id"`
	OwnershipScopeSHA256    string                         `json:"ownership_scope_sha256"`
	ConfigurationSHA256     string                         `json:"configuration_sha256"`
	ResourceIDs             []string                       `json:"resource_ids"`
	SourceID                string                         `json:"source_id"`
	OldProposalID           string                         `json:"old_proposal_id"`
	ASGARN                  string                         `json:"asg_arn"`
	AccountID               string                         `json:"account_id"`
	Region                  string                         `json:"region"`
	AllowedCandidates       []DecisionStagePolicyCandidate `json:"allowed_candidates"`
	SizeConstraintBasis     string                         `json:"size_constraint_basis"`
	ControllerScope         string                         `json:"controller_scope"`
	CustomerApprovalID      string                         `json:"customer_approval_id"`
	CustomerApprovalIssuer  string                         `json:"customer_approval_issuer"`
	CustomerApprovalSubject string                         `json:"customer_approval_subject"`
	ValidUntil              time.Time                      `json:"valid_until"`
	ExecutionAuthorized     bool                           `json:"execution_authorized"`
}

type DecisionStagePolicyCandidate struct {
	InstanceType    string `json:"instance_type"`
	ProposalID      string `json:"proposal_id"`
	TemplateID      string `json:"template_id"`
	TemplateVersion string `json:"template_version"`
	ImageID         string `json:"image_id"`
}

// These fields are returned only by the owner-defined DB resolver. The login
// has no policy INSERT, source-write, or generic entities privilege.
type decisionStagePolicyProjection struct {
	Policy                   *DecisionStagePolicy            `json:"policy"`
	PolicyRef                *Ref                            `json:"policy_ref"`
	RegistryActor            string                          `json:"registry_actor"`
	Sizing                   *DecisionStageSizingCatalog     `json:"sizing"`
	Controllers              []DecisionStageController       `json:"controllers"`
	ControllerDiscoveryRef   *Ref                            `json:"controller_discovery_ref"`
	ControllerCurrent        *decisionStageControllerCurrent `json:"controller_current"`
	ControllerScopeReference *Ref                            `json:"controller_scope_reference"`
	CurrentRefs              []Ref                           `json:"current_refs"`
	ReasonCodes              []string                        `json:"reason_codes"`
}

// Private DB currentness admission stays separate from the sealed stage refs.
// A routine read may issue another receipt without rewriting the original
// analytical input or claiming that the old observation itself is recent.
type decisionStageControllerCurrent struct {
	OriginalRef    Ref       `json:"original_ref"`
	LatestRef      Ref       `json:"latest_ref"`
	ObservedAt     time.Time `json:"observed_at"`
	CheckedAt      time.Time `json:"checked_at"`
	SemanticSHA256 string    `json:"semantic_sha256"`
}

func validateDecisionStageControllerCurrent(value *decisionStageControllerCurrent, original *Ref, now time.Time) error {
	if value == nil || original == nil || value.OriginalRef != *original || !stageRef(value.OriginalRef) || value.OriginalRef.Kind != "AWS_CONTROLLER_DISCOVERY" || !stageRef(value.LatestRef) || value.LatestRef.Kind != "AWS_CONTROLLER_DISCOVERY" || !shaPattern.MatchString(value.SemanticSHA256) || !ownershipUTC(value.ObservedAt) || !ownershipUTC(value.CheckedAt) || now.IsZero() || value.CheckedAt.Before(now.Add(-5*time.Second)) || value.CheckedAt.After(now.Add(5*time.Second)) || value.ObservedAt.Before(now.Add(-2*time.Minute)) || value.ObservedAt.After(now.Add(5*time.Second)) || value.ObservedAt.After(value.CheckedAt.Add(5*time.Second)) {
		return ErrEvidence
	}
	return nil
}

var stagePolicyInstanceType = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*\.[a-z0-9]+$`)
var stagePolicyTemplate = regexp.MustCompile(`^lt-(?:[a-f0-9]{8}|[a-f0-9]{17})$`)
var stagePolicyAMI = regexp.MustCompile(`^ami-(?:[a-f0-9]{8}|[a-f0-9]{17})$`)
var stagePolicyVersion = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)

func validateDecisionStagePolicy(p DecisionStagePolicy, q DecisionOptimizationQuery, now time.Time) error {
	if p.SchemaVersion != "1" || !idPattern.MatchString(p.ID) || p.Revision < 1 || p.Purpose != DecisionStagePolicyPurpose || p.Basis != DecisionStagePolicyBasis || p.TenantID != q.Scope.TenantID || p.WorkloadID != q.Scope.WorkloadID || !shaPattern.MatchString(p.OwnershipScopeSHA256) || p.ConfigurationSHA256 != q.Scope.ConfigurationSHA256 || Hash(p.ResourceIDs) != Hash(q.Scope.ResourceIDs) || !idPattern.MatchString(p.SourceID) || !idPattern.MatchString(p.OldProposalID) || !ownershipAccount.MatchString(p.AccountID) || p.Region != "eu-west-1" || p.CustomerApprovalID == "" || len(p.CustomerApprovalID) > 200 || p.CustomerApprovalIssuer == "" || len(p.CustomerApprovalIssuer) > 2048 || p.CustomerApprovalSubject == "" || len(p.CustomerApprovalSubject) > 256 || !ownershipUTC(p.ValidUntil) || !now.Before(p.ValidUntil) || p.ExecutionAuthorized || len(p.AllowedCandidates) < 1 || len(p.AllowedCandidates) > 8 {
		return ErrEvidence
	}
	seenTypes, seenProposals := map[string]bool{}, map[string]bool{}
	if p.SizeConstraintBasis != "CUSTOMER_APPROVED_EXHAUSTIVE_CATALOG" && p.SizeConstraintBasis != "BUSINESS_OR_LICENSE_RESTRICTION" || len(p.AllowedCandidates) == 1 && p.SizeConstraintBasis != "BUSINESS_OR_LICENSE_RESTRICTION" {
		return ErrEvidence
	}
	for i, candidate := range p.AllowedCandidates {
		version, versionErr := strconv.ParseUint(candidate.TemplateVersion, 10, 64)
		if versionErr != nil || version == 0 || !stagePolicyInstanceType.MatchString(candidate.InstanceType) || !idPattern.MatchString(candidate.ProposalID) || !stagePolicyTemplate.MatchString(candidate.TemplateID) || !stagePolicyVersion.MatchString(candidate.TemplateVersion) || !stagePolicyAMI.MatchString(candidate.ImageID) || seenTypes[candidate.InstanceType] || seenProposals[candidate.ProposalID] || i > 0 && p.AllowedCandidates[i-1].InstanceType >= candidate.InstanceType {
			return ErrEvidence
		}
		seenTypes[candidate.InstanceType] = true
		seenProposals[candidate.ProposalID] = true
	}
	if p.ControllerScope != "UNAVAILABLE" && p.ControllerScope != "CUSTOMER_REVIEWED_CONFIGURATION_ASG_ONLY" {
		return ErrEvidence
	}
	return nil
}

// loadDecisionStagePolicy selects facts rather than accepting them from the
// request. A missing policy or incomplete issued candidate/controller set is a
// typed gap. The returned refs name existing owner/ingester/evaluator rows.
func (r postgresDecisionStageRepository) loadDecisionStagePolicy(ctx context.Context, q DecisionOptimizationQuery, now time.Time) (decisionStagePolicyProjection, error) {
	var value decisionStagePolicyProjection
	if !r.valid(q) || now.IsZero() {
		return value, ErrEvidence
	}
	scope, err := json.Marshal(q.Scope)
	if err != nil {
		return value, ErrEvidence
	}
	err = r.transaction(ctx, func(tx pgx.Tx) error {
		var raw []byte
		if err := tx.QueryRow(ctx, "SELECT public.commitment_optimization_policy_inputs($1,$2,$3::jsonb)", r.worker.Tenant, q.RequestID, scope).Scan(&raw); err != nil {
			return err
		}
		if decodeDecisionPrivate(raw, &value, 32<<20) != nil {
			return ErrEvidence
		}
		if value.Policy == nil {
			if value.PolicyRef != nil || value.Sizing != nil || len(value.Controllers) > 0 || value.ControllerDiscoveryRef != nil || value.ControllerCurrent != nil || value.ControllerScopeReference != nil || len(value.ReasonCodes) == 0 {
				return ErrEvidence
			}
			return nil
		}
		p := *value.Policy
		if validateDecisionStagePolicy(p, q, now) != nil || value.PolicyRef == nil || value.PolicyRef.Kind != "WORKLOAD_SIZE_CONSTRAINT" || value.PolicyRef.ID != p.ID || !stageRef(*value.PolicyRef) || value.RegistryActor == "" {
			return ErrEvidence
		}
		if value.Sizing != nil {
			catalog := value.Sizing
			if catalog.Reference != *value.PolicyRef || catalog.ConfigurationSHA256 != q.Scope.ConfigurationSHA256 || len(catalog.AllowedInstanceTypes) != len(p.AllowedCandidates) || len(catalog.Joins) != len(p.AllowedCandidates) || len(catalog.CurrentInstanceTypes) != len(q.Scope.ResourceIDs) {
				return ErrEvidence
			}
			for _, id := range q.Scope.ResourceIDs {
				if catalog.CurrentInstanceTypes[id] == "" {
					return ErrEvidence
				}
			}
			for i, candidate := range p.AllowedCandidates {
				join := catalog.Joins[i]
				input := join.Input
				template := input.Scope.CandidateTemplate
				if catalog.AllowedInstanceTypes[i] != candidate.InstanceType || input.RequestID != join.Reference.ID || !stageRef(join.Reference) || input.Profile.WorkloadID != q.Scope.WorkloadID || input.Assessment.Selection.Groups.OldProposal.ID != p.OldProposalID || input.Assessment.Selection.Groups.CandidateProposal.ID != candidate.ProposalID || template == nil || template.InstanceType != candidate.InstanceType || template.ID != candidate.TemplateID || template.Version != candidate.TemplateVersion || template.ImageID != candidate.ImageID || Hash(input.Scope.Scope.CurrentMemberIDs) != Hash(q.Scope.ResourceIDs) {
					return ErrEvidence
				}
				if join.ObservedAt.IsZero() || join.ObservedAt.After(now.Add(5*time.Second)) || now.Sub(input.Assessment.ObservedAt) > 2*time.Minute || input.Assessment.ObservedAt.After(now.Add(5*time.Second)) || now.Sub(input.Scope.Scope.ObservedAt) > 5*time.Minute {
					return ErrEvidence
				}
				decision, err := fleetdecision.Build(input, join.ObservedAt)
				if err != nil || Hash(decision) != join.Reference.SHA256 {
					return ErrEvidence
				}
			}
		}
		if value.ControllerDiscoveryRef != nil || value.ControllerCurrent != nil || value.ControllerScopeReference != nil || len(value.Controllers) > 0 {
			if validateDecisionStageControllerCurrent(value.ControllerCurrent, value.ControllerDiscoveryRef, time.Now().UTC()) != nil {
				return ErrEvidence
			}
			if p.ControllerScope != "CUSTOMER_REVIEWED_CONFIGURATION_ASG_ONLY" || value.ControllerDiscoveryRef == nil || !stageRef(*value.ControllerDiscoveryRef) || value.ControllerDiscoveryRef.Kind != "AWS_CONTROLLER_DISCOVERY" || value.ControllerScopeReference == nil || value.ControllerScopeReference.Kind != "WORKLOAD_CONTROLLER_SCOPE" || value.ControllerScopeReference.ID != p.ID || value.ControllerScopeReference.SHA256 != value.PolicyRef.SHA256 || len(value.Controllers) != 1 {
				return ErrEvidence
			}
			c := value.Controllers[0]
			ids := append([]string{}, c.MemberIDs...)
			sort.Strings(ids)
			if c.Reference != *value.ControllerDiscoveryRef || c.ConfigurationSHA256 != q.Scope.ConfigurationSHA256 || Hash(ids) != Hash(q.Scope.ResourceIDs) || c.Minimum < 1 || c.Maximum < c.Minimum || c.Desired < c.Minimum || c.Desired > c.Maximum {
				return ErrEvidence
			}
		}
		return nil
	})
	if err != nil {
		return decisionStagePolicyProjection{}, err
	}
	return value, nil
}
