"""Explicit synthetic economic components; not genuine AWS acceptance."""
import copy
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import unittest

from autopilot.aws_service_model import evaluate_aws_service, MODEL_KIND
from autopilot.model import EvidenceError


def ref(name):
    return {"kind":"SYNTHETIC_AWS_SERVICE_COMPONENT","id":name,"version":"1","sha256":hashlib.sha256(name.encode()).hexdigest()}


def fixture(family, days=14):
    end=datetime(2026,10,20,tzinfo=timezone.utc)
    start=end-timedelta(days=days)
    stamp=lambda v:v.isoformat().replace("+00:00","Z")
    native={"ECS":"ecs:eu-west-1:111122223333:service/cluster/service","DYNAMODB":"dynamodb:eu-west-1:111122223333:table/table","ELASTICACHE":"elasticache:eu-west-1:111122223333:cluster:cache","ELB":"elasticloadbalancing:eu-west-1:111122223333:loadbalancer/app/web/id"}[family]
    binding={"tenant_id":"synthetic-tenant","provider":"AWS","account_id":"111122223333","region":"eu-west-1","resource_id":"synthetic-resource","provider_resource_id":"arn:aws:"+native,"workload_id":"synthetic-workload"}
    limits={"cpu_headroom_fraction":"0.2","memory_headroom_fraction":"0.2","burst_requirements_known":True,"autoscaling_reviewed":True,"read_target_utilization_fraction":"0.5","write_target_utilization_fraction":"0.5","min_read_capacity_units":"1","min_write_capacity_units":"1","max_swap_bytes":"0","max_evictions":"0","max_replication_lag_seconds":"1","min_replicas_per_shard":"1","recovery_requirements_known":True,"failover_required":True,"purpose":"ACTIVE","low_requests_per_second":"1","low_bytes_per_second":"1000"}
    runtime={"cpuArchitecture":"X86_64","operatingSystemFamily":"LINUX"}
    configs={"ECS":{"launchType":"FARGATE","runningCount":1,"desiredCount":1,"pendingCount":0,"deployments":[{"rolloutState":"COMPLETED"}],"task_definition":{"cpu":"1024","memory":"2048","runtimePlatform":runtime},"scalable_targets":[],"scaling_policies":[]},"DYNAMODB":{"TableName":"table","BillingModeSummary":{"BillingMode":"PROVISIONED"},"ProvisionedThroughput":{"ReadCapacityUnits":1000,"WriteCapacityUnits":500}},"ELASTICACHE":{"Engine":"valkey","EngineVersion":"8.0","CacheNodeType":"cache.synthetic.large","CacheNodes":{"CacheNode":[{"CacheNodeId":"0001"}]}},"ELB":{"subtype":"ALB","LoadBalancerName":"web","target_groups":[]}}
    shapes={"ECS":{"candidates":[{"id":"half","cpu_units":"512","memory_mib":"1024","architecture":"X86_64","operating_system_family":"LINUX","source_ref":ref("fargate-capability")}]},"DYNAMODB":{"candidates":[]},"ELASTICACHE":{"current":{"memory_bytes":"17179869184","vcpu":"4"},"candidates":[{"id":"smaller","memory_bytes":"8589934592","vcpu":"2","engine":"valkey","engine_version":"8.0","preserves_topology":True,"source_ref":ref("cache-physical-capability")}]},"ELB":{"candidates":[]}}
    series={"ECS":[("CPUUtilization","Maximum","10","Percent"),("MemoryUtilization","Maximum","20","Percent"),("RunningTaskCount","Maximum","1","Count"),("RunningTaskCount","Minimum","1","Count")],"DYNAMODB":[("ConsumedReadCapacityUnits","Sum","1","Count"),("ConsumedWriteCapacityUnits","Sum","1","Count"),("ReadThrottleEvents","Sum","0","Count"),("WriteThrottleEvents","Sum","0","Count")],"ELASTICACHE":[("CPUUtilization","Maximum","10","Percent"),("EngineCPUUtilization","Maximum","10","Percent"),("DatabaseMemoryUsagePercentage","Maximum","10","Percent"),("SwapUsage","Maximum","0","Bytes"),("Evictions","Sum","0","Count"),("ReplicationLag","Maximum","0","Seconds"),("CurrConnections","Maximum","1","Count"),("CacheHits","Sum","100","Count"),("CacheMisses","Sum","1","Count")],"ELB":[("RequestCount","Sum","0","Count"),("ProcessedBytes","Sum","0","Bytes"),("ActiveConnectionCount","Maximum","0","Count")]}
    metrics=[]
    for n in range(days):
        for name,stat,value,unit in series[family]:
            metrics.append({"metric":name,"statistic":stat,"value":value,"unit":unit,"sample_count":"1440","period_seconds":86400,"source_time":stamp(start+timedelta(days=n)),"provider_resource_id":binding["provider_resource_id"],"dimensions":{}})
    # Model-unit projections only: these are explicitly synthetic work samples,
    # never receipts from the guarded machine ingress or connected acceptance.
    activity=[]
    if family=="ECS":
        for n in range(days):
            for name,stat,value in (("AcceptedWork","Sum","100"),("CompletedWork","Sum","100"),("RejectedWork","Sum","0"),("Backlog","Maximum","0"),("InFlightWork","Maximum","0")):
                activity.append({"metric":name,"statistic":stat,"value":value,"unit":"Count","sample_count":"1440","period_seconds":86400,"source_time":stamp(start+timedelta(days=n)),"provider_resource_id":binding["provider_resource_id"],"dimensions":{}})
    hours=Decimal(days*24)
    charges={"ECS":[("FARGATE_CPU",hours,"0.04","vCPU-Hours"),("FARGATE_MEMORY",hours*2,"0.004","GB-Hours")],"DYNAMODB":[("READ_PROVISIONED",hours*1000,"0.0001","Hrs"),("WRITE_PROVISIONED",hours*500,"0.0004","Hrs")],"ELASTICACHE":[("CACHE_NODE",hours,"1","Hrs")],"ELB":[("CONTINUING",hours,"0.02","Hrs")]}
    components=[];rates=[]
    for component,quantity,price,unit in charges[family]:
        amount=str(quantity*Decimal(price));row={"id":component,"component":component,"amount":amount,"effective_amount":amount,"quantity":str(quantity),"rate":price,"unit":unit,"currency":"GBP","avoidability":"CONTINUING" if component=="CONTINUING" else "MARGINAL","source_ref":ref(component)};components.append(row)
        if component!="CONTINUING":rates.append({"id":component,"component":component,"rate":price,"unit":unit,"currency":"GBP","bracket_resolved":True,"source_ref":ref(component)})
    if family=="DYNAMODB":
        for component in ("READ_REQUEST","WRITE_REQUEST"):rates.append({"id":component,"component":component,"rate":"0.000001","unit":"Requests","currency":"GBP","bracket_resolved":True,"source_ref":ref(component)})
    if family=="ELASTICACHE":rates.append({"id":"candidate-price","component":"CACHE_NODE","candidate_key":"smaller","rate":"0.5","unit":"Hrs","currency":"GBP","bracket_resolved":True,"source_ref":ref("candidate-price")})
    return {"schema_version":"1","model_version":"aws-service-v1","model_kind":MODEL_KIND,"binding":binding,"family":family,"now":stamp(end+timedelta(hours=1)),"configuration":configs[family],"snapshot_ref":ref("native-snapshot"),"observations":{"start":stamp(start),"end":stamp(end),"metrics":metrics,"activity":activity},"capabilities":shapes[family],"policy":{"owner":"customer-team","configuration_authority":"TERRAFORM","criticality":"NON_PRODUCTION","seasonal":False,"service_constraints":limits},"billing":{"currency":"GBP","start":stamp(start),"end":stamp(end),"complete":True,"scope_complete":True,"marginal_pricing_known":True,"commitment_scope_known":True,"capacity_request_unit_equivalence_known":True,"components":components,"rate_witnesses":rates},"source_refs":[ref("native-snapshot")]}


def candidate(data,identity):
    return next(c for c in evaluate_aws_service(data)["candidates"] if c["id"]==identity)


class ECSServiceEconomicsTests(unittest.TestCase):
    def test_missing_or_gapped_work_history_blocks_all_ecs_decisions(self):
        for change in ("missing","gap","current-only"):
            with self.subTest(change=change):
                d=fixture("ECS")
                if change=="missing":d["observations"]["activity"]=[]
                elif change=="gap":d["observations"]["activity"].pop()
                else:d["observations"]["activity"]=d["observations"]["activity"][-5:]
                result=evaluate_aws_service(d)
                self.assertEqual(result["status"],"BLOCKED")
                self.assertEqual(result["economically_analysed_source_record_ids"],[])
                self.assertIn("ECS_INDEPENDENT_WORKLOAD_ACTIVITY_REQUIRED",result["reason_codes"])
                for row in [result]+result["candidates"]:
                    self.assertEqual(row["status"],"BLOCKED")
                    self.assertIsNotNone(row["economics"]["current_window_cost"])
                    self.assertIsNone(row["economics"]["candidate_window_cost"])
                    self.assertIsNone(row["economics"]["estimated_window_saving"])

    def test_native_container_floor_and_steady_cohort_are_independent(self):
        d=fixture("ECS")
        d["configuration"]["task_definition"]["containerDefinitions"]=[{"cpu":768,"memoryReservation":1536}]
        self.assertIn("ECS_CONTAINER_REQUIREMENTS_EXCEED_CANDIDATE",candidate(d,"half")["reason_codes"])
        d=fixture("ECS");d["configuration"]["fargate_cohort"]={"schema_version":"ECS_FARGATE_SERVICE_COHORT_V1"}
        for row in d["observations"]["metrics"]:
            if row["metric"]=="RunningTaskCount" and row["statistic"]=="Maximum":row["value"]="2"
        self.assertIn("ECS_STEADY_NATIVE_TASK_COHORT_HISTORY_REQUIRED",candidate(d,"half")["reason_codes"])

    def test_fargate_cpu_memory_customer_economics_and_no_change(self):
        d=fixture("ECS");before=copy.deepcopy(d);r=candidate(d,"half")
        self.assertEqual(r["status"],"RECOMMENDED");self.assertGreater(Decimal(r["economics"]["estimated_window_saving"]),0);self.assertEqual(d,before)
        d["capabilities"]["candidates"][0].update(cpu_units="1024",memory_mib="2048")
        self.assertEqual(candidate(d,"half")["status"],"NO_CHANGE")

    def test_memory_peak_missing_data_autoscaling_and_ec2_block(self):
        for change in ("memory","missing","scaling","ec2"):
            with self.subTest(change=change):
                d=fixture("ECS")
                if change=="memory":
                    for row in d["observations"]["metrics"]:
                        if row["metric"]=="MemoryUtilization":row["value"]="95"
                elif change=="missing":d["observations"]["metrics"].pop()
                elif change=="scaling":d["policy"]["service_constraints"]["autoscaling_reviewed"]=False
                else:d["configuration"]["launchType"]="EC2"
                r=candidate(d,"half");self.assertEqual(r["status"],"BLOCKED");self.assertIsNone(r["economics"]["estimated_window_saving"])

    def test_slo_and_tenant_ref_confusion(self):
        d=fixture("ECS");d["policy"]["service_constraints"]["max_latency_ms"]="100"
        self.assertIn("AWS_SERVICE_APPLICATION_LATENCY_EVIDENCE_REQUIRED",candidate(d,"half")["reason_codes"])
        d["snapshot_ref"]["binding"]={"tenant_id":"foreign"}
        with self.assertRaises(EvidenceError):evaluate_aws_service(d)


class DynamoDBServiceEconomicsTests(unittest.TestCase):
    def test_capacity_and_mode_customer_break_even(self):
        d=fixture("DYNAMODB");r=candidate(d,"dynamodb-capacity")
        self.assertEqual(r["status"],"RECOMMENDED");self.assertEqual(r["proposed_configuration"]["read_capacity_units"],"2.000000000000")
        self.assertEqual(r["proposed_configuration"]["peak_basis"],"CONSERVATIVE_PERIOD_TOTAL_PER_SECOND_UPPER_BOUND")
        self.assertIsNotNone(candidate(d,"dynamodb-mode")["proposed_configuration"]["economic_break_even"])

    def test_throttle_missing_commitment_and_unknown_unit_mapping(self):
        d=fixture("DYNAMODB");d["observations"]["metrics"][2]["value"]="1"
        self.assertIn("DYNAMODB_THROTTLING_BLOCKS_REDUCTION",candidate(d,"dynamodb-capacity")["reason_codes"])
        d=fixture("DYNAMODB");d["billing"]["commitment_scope_known"]=False
        self.assertIsNone(candidate(d,"dynamodb-capacity")["economics"]["estimated_window_saving"])
        d=fixture("DYNAMODB");d["billing"]["capacity_request_unit_equivalence_known"]=False
        self.assertEqual(candidate(d,"dynamodb-mode")["status"],"BLOCKED")

    def test_billing_replay_altered_amount_and_currency(self):
        d=fixture("DYNAMODB");d["billing"]["components"].append(copy.deepcopy(d["billing"]["components"][0]))
        with self.assertRaises(EvidenceError):evaluate_aws_service(d)
        d=fixture("DYNAMODB");d["billing"]["components"][0]["amount"]="1"
        with self.assertRaises(EvidenceError):evaluate_aws_service(d)
        d=fixture("DYNAMODB");d["billing"]["components"][0]["currency"]="EUR"
        self.assertIsNone(candidate(d,"dynamodb-capacity")["economics"]["estimated_window_saving"])


class ElastiCacheServiceEconomicsTests(unittest.TestCase):
    def test_native_physical_candidate_and_negative_outcome(self):
        d=fixture("ELASTICACHE");self.assertEqual(candidate(d,"smaller")["status"],"RECOMMENDED")
        d["billing"]["rate_witnesses"][-1]["rate"]="2"
        r=candidate(d,"smaller");self.assertEqual(r["status"],"NO_CHANGE");self.assertLess(Decimal(r["economics"]["estimated_window_saving"]),0)

    def test_memory_high_swap_failover_and_missing_capability(self):
        for change in ("memory","swap","failover","physical"):
            d=fixture("ELASTICACHE")
            if change=="memory":
                for row in d["observations"]["metrics"]:
                    if row["metric"]=="DatabaseMemoryUsagePercentage":row["value"]="95"
            elif change=="swap":
                for row in d["observations"]["metrics"]:
                    if row["metric"]=="SwapUsage":row["value"]="1"
            elif change=="failover":d["capabilities"]["candidates"][0]["preserves_topology"]=False
            else:d["capabilities"]["current"]={}
            self.assertEqual(candidate(d,"smaller")["status"],"BLOCKED")


class LoadBalancerServiceEconomicsTests(unittest.TestCase):
    def test_explicit_zero_reviews_never_claim_savings_or_delete(self):
        d=fixture("ELB");result=evaluate_aws_service(d)
        self.assertEqual(candidate(d,"load-balancer-idle")["status"],"RECOMMENDED")
        for r in [result]+result["candidates"]:
            self.assertFalse(r["pre_execution_ready"]);self.assertFalse(r["execution_authorized"]);self.assertIsNone(r["verified_saving"]);self.assertIsNone(r["economics"]["estimated_window_saving"])
        self.assertEqual(result["economically_analysed_source_record_ids"],[])

    def test_sparse_no_traffic_is_unknown_and_production_history(self):
        d=fixture("ELB");d["observations"]["metrics"]=[]
        self.assertEqual(candidate(d,"load-balancer-idle")["status"],"BLOCKED")
        d=fixture("ELB");d["policy"]["criticality"]="PRODUCTION"
        self.assertIn("AWS_SERVICE_INSUFFICIENT_OBSERVATION_HISTORY",evaluate_aws_service(d)["reason_codes"])
        d=fixture("ELB");d["observations"]["metrics"].append(copy.deepcopy(d["observations"]["metrics"][0]))
        with self.assertRaises(EvidenceError):evaluate_aws_service(d)


if __name__=="__main__":unittest.main()
