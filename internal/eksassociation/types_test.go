package eksassociation

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/kubernetes"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"testing"
)

func hasReason(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func testRegistration() Registration {
	return Registration{ID: "eks-source", TenantID: "tenant", Kind: Kind, AccountID: "111122223333", Region: "eu-west-1", ClusterARN: "arn:aws:eks:eu-west-1:111122223333:cluster/pilot", ReadRoleBindingID: "aws-reader", KubernetesReadBindingID: "kube-reader", Version: 1, Enabled: true}
}
func nativeResource(kind, id string, cfg model.Document) model.Document {
	return model.Document{"id": id, "resource_type": kind, "account_id": "111122223333", "region": "eu-west-1", "aws_service_configuration": cfg}
}
func TestEKSManagedNodeAssociationRequiresNativeMembershipAndCanonicalIdentity(t *testing.T) {
	r := testRegistration()
	s := kubernetes.IdentitySnapshot{ClusterID: "observed-cluster-uid", Nodes: []kubernetes.IdentityNode{{UID: "node-uid", Name: "worker", ProviderID: "aws:///eu-west-1a/i-0123456789abcdef0", Zone: "eu-west-1a", Nodegroup: "workers"}}}
	group := nativeResource("EKS_NODE_GROUP", "group", model.Document{"clusterName": "pilot", "nodegroupName": "workers", "native_auto_scaling_group_names": []string{"eks-workers"}})
	ec2 := nativeResource("EC2", "ec2", nil)
	ec2["provider_resource_id"] = "i-0123456789abcdef0"
	member := model.Document{"instance_id": "i-0123456789abcdef0", "asg_name": "eks-workers", "account_id": r.AccountID, "region": r.Region, "zone": "eu-west-1a", "state": "running"}
	if d := Associate(r, s, []model.Document{group, ec2}, nil); d["status"] == "ASSOCIATED" {
		t.Fatal("node labels manufactured native membership")
	}
	d := Associate(r, s, []model.Document{group, ec2}, []model.Document{member})
	if d["status"] != "ASSOCIATED" || d["execution_authorized"] != false || d["verified_saving"] != nil || Rows(d["nodes"])[0]["nodegroup_resource_id"] != "group" {
		t.Fatalf("point identity failed: %#v", d)
	}
	member["account_id"] = "999900001111"
	if d := Associate(r, s, []model.Document{group, ec2}, []model.Document{member}); d["status"] == "ASSOCIATED" {
		t.Fatal("foreign native owner associated")
	}
}

func TestEKSRequestAllocationReviewRequiresExactPlacementAndNeverClaimsSavings(t *testing.T) {
	r := testRegistration()
	r.WorkloadBindings = []kubernetes.IdentityWorkloadBinding{{WorkloadID: "web", Namespace: "apps", NamespaceUID: "namespace-uid", Deployment: "web", DeploymentUID: "deployment-uid"}}
	node := kubernetes.IdentityNode{UID: "node-uid", Name: "worker", ProviderID: "aws:///eu-west-1a/i-0123456789abcdef0", Zone: "eu-west-1a", Architecture: "amd64", CPUAllocatableMilli: 3800, MemoryAllocatableBytes: 7 << 30, CapacityKnown: true, Nodegroup: "workers", Ready: true}
	pod := kubernetes.IdentityPod{UID: "pod-uid", Node: "worker", Scheduled: true, Running: true, Phase: "Running", CPURequestMilli: 250, MemoryRequestBytes: 128 << 20, CPULimitMilli: 1000, MemoryLimitBytes: 512 << 20, ResourceRequestsKnown: true, ResourceLimitsKnown: true}
	s := kubernetes.IdentitySnapshot{ClusterID: "observed-cluster-uid", Nodes: []kubernetes.IdentityNode{node}, Workloads: []kubernetes.IdentityWorkload{{Binding: r.WorkloadBindings[0], NamespaceUID: "namespace-uid", DeploymentUID: "deployment-uid", Pods: []kubernetes.IdentityPod{pod}}}}
	group := nativeResource("EKS_NODE_GROUP", "group", model.Document{"clusterName": "pilot", "nodegroupName": "workers", "native_auto_scaling_group_names": []string{"eks-workers"}})
	ec2 := nativeResource("EC2", "ec2", nil)
	ec2["provider_resource_id"] = "i-0123456789abcdef0"
	member := model.Document{"instance_id": "i-0123456789abcdef0", "asg_name": "eks-workers", "account_id": r.AccountID, "region": r.Region, "zone": "eu-west-1a", "state": "running"}
	d := Associate(r, s, []model.Document{group, ec2}, []model.Document{member})
	assessments := Rows(d["request_assessments"])
	if len(assessments) != 1 || assessments[0]["status"] != "REVIEW_ONLY" || assessments[0]["recommendation_kind"] != "KUBERNETES_REQUEST_ALLOCATION_REVIEW" || model.Number(assessments[0], "cpu_request_milli") != 250 || model.Number(assessments[0], "memory_request_bytes") != 128<<20 || model.Number(assessments[0], "cpu_limit_milli") != 1000 || model.Number(assessments[0], "memory_limit_bytes") != 512<<20 || assessments[0]["observed_usage"] != nil || assessments[0]["estimated_saving"] != nil || assessments[0]["verified_saving"] != nil || assessments[0]["execution_authorized"] != false {
		t.Fatalf("request review overstated or unavailable: %#v", d)
	}
	if !hasReason(model.Strings(assessments[0], "reason_codes"), "K8S_HISTORICAL_OBSERVED_USAGE_REQUIRED") || !hasReason(model.Strings(assessments[0], "reason_codes"), "K8S_COST_REALIZATION_UNPROVEN") {
		t.Fatalf("review blockers missing: %#v", assessments[0])
	}
	blocked := s
	blocked.Nodes = []kubernetes.IdentityNode{{UID: node.UID, Name: node.Name, ProviderID: "aws:///eu-west-1a/i-0123456789abcdef0", Zone: node.Zone, Nodegroup: node.Nodegroup, Ready: true}}
	blockedAssessment := Rows(Associate(r, blocked, []model.Document{group, ec2}, nil)["request_assessments"])[0]
	if blockedAssessment["status"] != "BLOCKED" || blockedAssessment["cpu_request_milli"] != nil || !hasReason(model.Strings(blockedAssessment, "reason_codes"), "EKS_WORKLOAD_CAPACITY_ASSOCIATION_INCOMPLETE") {
		t.Fatalf("unknown node association allowed workload allocation: %#v", blockedAssessment)
	}
}

func TestEKSFargateAssociationNeedsObservedScheduledRunningExactProfile(t *testing.T) {
	r := testRegistration()
	profile := nativeResource("EKS_FARGATE_PROFILE", "profile", model.Document{"clusterName": "pilot", "fargateProfileName": "web-profile", "status": "ACTIVE", "selectors": []model.Document{{"namespace": "apps-*", "labels": model.Document{"app": "web"}}}})
	s := kubernetes.IdentitySnapshot{ClusterID: "uid", Nodes: []kubernetes.IdentityNode{{UID: "node", Name: "fargate-node", ComputeType: "fargate", Profile: "web-profile", Ready: true}}, Workloads: []kubernetes.IdentityWorkload{{Binding: kubernetes.IdentityWorkloadBinding{WorkloadID: "web", Namespace: "apps-pilot"}, Pods: []kubernetes.IdentityPod{{UID: "pod", Node: "fargate-node", Labels: map[string]string{"app": "web", "eks.amazonaws.com/fargate-profile": "web-profile"}, Phase: "Running", Scheduled: true, Running: true}}}}}
	if d := Associate(r, s, []model.Document{profile}, nil); d["status"] != "ASSOCIATED" || Rows(d["nodes"])[0]["fargate_profile_resource_id"] != "profile" {
		t.Fatalf("observed Fargate placement unavailable: %#v", d)
	}
	for _, change := range []string{"pending", "missing-profile", "not-ready"} {
		copy := s
		copy.Nodes = append([]kubernetes.IdentityNode{}, s.Nodes...)
		copy.Workloads = append([]kubernetes.IdentityWorkload{}, s.Workloads...)
		copy.Workloads[0].Pods = append([]kubernetes.IdentityPod{}, s.Workloads[0].Pods...)
		switch change {
		case "pending":
			copy.Workloads[0].Pods[0].Scheduled = false
		case "missing-profile":
			copy.Nodes[0].Profile = ""
		case "not-ready":
			copy.Nodes[0].Ready = false
		}
		if d := Associate(r, copy, []model.Document{profile}, nil); d["status"] == "ASSOCIATED" {
			t.Fatalf("%s was accepted", change)
		}
	}
}
func TestEKSRegistrationRejectsForeignIdentityAndDuplicateWorkloadScope(t *testing.T) {
	r := testRegistration()
	if Validate(r) != nil {
		t.Fatal("valid registration rejected")
	}
	r.ClusterARN = "arn:aws:eks:eu-west-1:999900001111:cluster/pilot"
	if Validate(r) == nil {
		t.Fatal("foreign account accepted")
	}
	r = testRegistration()
	r.WorkloadBindings = []kubernetes.IdentityWorkloadBinding{{WorkloadID: "w", Namespace: "apps", NamespaceUID: "n", Deployment: "web", DeploymentUID: "d"}, {WorkloadID: "w", Namespace: "apps", NamespaceUID: "n", Deployment: "web", DeploymentUID: "d"}}
	if Validate(r) == nil {
		t.Fatal("ambiguous workload scope accepted")
	}
}
