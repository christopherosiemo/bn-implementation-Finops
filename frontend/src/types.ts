import type { components } from "./api.generated";

export type Document = Omit<
  components["schemas"]["Document"],
  "id" | "version"
> & { id: string; version: number };
export type ConnectAccountRequest =
  components["schemas"]["ConnectAccountRequest"];
export type CreatePlanRequest = components["schemas"]["CreatePlanRequest"];
export type WireDashboard = components["schemas"]["Dashboard"];
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
  hourly_effective_cost: string;
  monthly_effective_cost: string;
  eligibility: string | boolean;
  blockers: string[];
  currency?: string;
}
export interface Recommendation extends Document {
  workload_id: string;
  title: string;
  category: string;
  risk_class: string;
  status: string;
  reason_code?: string;
  monthly_saving: string;
  annual_saving: string;
  currency?: string;
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
export interface ChangePlan extends Document {
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
export interface Saving extends Document {
  execution_id: string;
  status: string;
  verified_saving: string | null;
  expected_baseline_cost: string;
  actual_cost: string;
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
