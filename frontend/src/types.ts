import type { components } from "./api.generated";

export type Document = Omit<
  components["schemas"]["Document"],
  "id" | "version"
> & { id: string; version: number };
export type ConnectAccountRequest =
  components["schemas"]["ConnectAccountRequest"];
export type CreatePlanRequest = components["schemas"]["CreatePlanRequest"];
export type WireDashboard = components["schemas"]["Dashboard"];
export interface EvidenceFields {
  pre_execution_ready?: boolean;
  verification_status?: string;
  baseline_id?: string | null;
  measurement_id?: string | null;
  readiness_id?: string | null;
  proof_set_id?: string | null;
  dependency_status?: "READY" | "BLOCKED" | "UNKNOWN";
  dependency_reasons?: string[];
  dependency_review_id?: string | null;
  dependency_graph_hash?: string | null;
  slo_status?: "CLEAR" | "BLOCKED";
  slo_reasons?: string[];
  slo_objective_id?: string | null;
  slo_objective_version?: number | null;
  slo_objective_hash?: string | null;
  slo_evaluation_id?: string | null;
  slo_evaluation_hash?: string | null;
  slo_evaluation?: components["schemas"]["SloEvaluation"];
  activation_at?: string | null;
  evidence_refs?: unknown[];
  source_refs?: components["schemas"]["SourceReference"][];
}
export type Readiness = components["schemas"]["Readiness"];
export type DependencyNode = components["schemas"]["DependencyNode"];
export type DependencyEdge = components["schemas"]["DependencyEdge"];
export type DependencyEdgeInput = components["schemas"]["DependencyEdgeInput"];
export type DependencyEdgeType = components["schemas"]["DependencyEdgeType"];
export type DependencyReview = components["schemas"]["DependencyReview"];
export type ResourceGraph = components["schemas"]["ResourceGraph"];
export type SloObjective = components["schemas"]["SloObjective"];
export type SloObjectiveRequest = components["schemas"]["SloObjectiveRequest"];
export type SloSource = components["schemas"]["SloSource"];
export type SloEvaluation = components["schemas"]["SloEvaluation"];
export type SloEvaluationSnapshot =
  components["schemas"]["SloEvaluationSnapshot"];
export interface Organization extends Document {
  name: string;
  paused: boolean;
}
export interface Account extends Document {
  name: string;
  provider: string;
  account_id: string;
  region: string;
  status?: string;
}
export interface Workload extends Document {
  name: string;
  environment: string;
  owner: string;
  timezone: string;
  incident: string;
  deployment: string;
  job: string;
  signals_at: string;
}
export interface Resource extends Document {
  name: string;
  provider: string;
  resource_type: string;
  provider_resource_id: string;
  workload_id: string;
  environment: string;
  state: string;
  configuration_authority: string;
  hourly_effective_cost: string | null;
  monthly_effective_cost: string | null;
  eligibility: string | boolean;
  blockers: string[];
  currency?: string | null;
}
export interface Recommendation extends Document, EvidenceFields {
  resource_id?: string;
  workload_id: string;
  title: string;
  category: string;
  risk_class: string;
  status: string;
  reason_code?: string;
  monthly_saving: string | null;
  annual_saving: string | null;
  currency?: string | null;
  confidence: number | string;
  evidence: unknown;
}
export interface Schedule extends Document {
  workload_id: string;
  stop_time: string;
  ready_time: string;
  timezone: string;
  days: number[];
  mode: string;
  paused: boolean;
  skip_next_stop: boolean;
}
export interface ChangePlan extends Document, EvidenceFields {
  resource_id?: string;
  recommendation_id: string;
  schedule_id: string;
  status: string;
  risk_class: string;
  operations: unknown;
  expires_at: string;
}
export interface Execution extends Document {
  change_plan_id: string;
  status: string;
  stage: string;
  resource_id: string;
  started_at: string;
  restoration_owned: boolean;
  error?: string;
}
export interface Saving extends Document, EvidenceFields {
  execution_id: string;
  status: string;
  verified_saving: string | null;
  expected_baseline_cost: string | null;
  actual_cost: string | null;
  currency: string;
  reason_code?: string;
}
export interface Audit extends Document {
  action: string;
  actor: string;
  timestamp: string;
  resource: string;
}
export interface Dashboard {
  org: Organization;
  fixture: boolean;
  cloud_accounts: Account[];
  resources: Resource[];
  workloads: Workload[];
  recommendations: Recommendation[];
  policies: Document[];
  schedules: Schedule[];
  change_plans: ChangePlan[];
  executions: Execution[];
  savings: Saving[];
  audit: Audit[];
  data_quality: Document[];
  readiness?: Readiness[];
  source_connections?: (Document & components["schemas"]["SourceConnection"])[];
  activity_sources?: Document[];
  dependency_graph?: ResourceGraph;
  slo_objectives?: SloObjective[];
  slo_sources?: SloSource[];
  slo_evaluations?: SloEvaluationSnapshot[];
}
export type Page =
  | "overview"
  | "workloads"
  | "recommendations"
  | "schedules"
  | "executions"
  | "savings"
  | "connections"
  | "audit";
