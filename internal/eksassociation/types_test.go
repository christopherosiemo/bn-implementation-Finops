package eksassociation

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/kubernetes"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"testing"
)

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
