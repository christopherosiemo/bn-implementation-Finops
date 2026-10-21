package lambdacost

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"testing"
)

func nativeComparableTestConfig() model.Document {
	presence := model.Document{}
	for _, key := range []string{"FunctionArn", "Version", "CodeSha256", "Runtime", "Handler", "PackageType", "Architectures", "Timeout", "EphemeralStorage", "VpcConfig", "Layers", "FileSystemConfigs", "Environment", "RuntimeVersionConfig", "Role", "TracingConfig", "DeadLetterConfig", "LoggingConfig", "SnapStart"} {
		presence[key] = true
	}
	return model.Document{"native_configuration_response_observed": true, "native_field_presence": presence, "base_function_arn": "arn:aws:lambda:eu-west-1:111122223333:function:processor", "version": "1", "model": "EVENT_DEFAULT", "code_sha256": Hash("code"), "runtime": "python3.13", "handler": "main.handler", "package_type": "Zip", "architecture": "x86_64", "execution_role_metadata": "arn:aws:iam::111122223333:role/customer", "runtime_version": model.Document{"RuntimeVersionArn": "arn:aws:lambda:eu-west-1::runtime:immutable-version"}, "timeout_seconds": 30, "ephemeral_storage_mb": 512, "environment_metadata": model.Document{"present": true, "variables_observed": true, "error_present": false, "variable_count": 0, "values_redacted": true}, "vpc": model.Document{"VpcId": "", "SubnetIds": []string{}, "SecurityGroupIds": []string{}, "Ipv6AllowedForDualStack": false}, "layers": []model.Document{}, "file_systems": []model.Document{}, "tracing": model.Document{}, "dead_letter": model.Document{}, "logging": model.Document{}, "snap_start": model.Document{}, "memory_size_mb": 2048, "reserved_concurrency": 20, "provisioned_concurrency": []model.Document{}}
}
func TestLambdaNonMemoryFingerprintRequiresObservedEmptyEnvironmentAndFullConfiguration(t *testing.T) {
	c := nativeComparableTestConfig()
	before := Hash(c)
	fingerprint, rs := NonMemoryFingerprint(c)
	if fingerprint == "" || len(rs) > 0 {
		t.Fatal(rs)
	}
	if Hash(c) != before {
		t.Fatal("fingerprint mutated native evidence")
	}
	for _, change := range []string{"nonempty", "missing_variables", "environment_error", "missing_full_get", "missing_native_field", "filesystem", "provisioned", "weighted"} {
		t.Run(change, func(t *testing.T) {
			d := Document(c)
			switch change {
			case "nonempty":
				Document(d["environment_metadata"])
				env := Document(d["environment_metadata"])
				env["variable_count"] = 1
				d["environment_metadata"] = env
			case "missing_variables":
				env := Document(d["environment_metadata"])
				env["variables_observed"] = false
				d["environment_metadata"] = env
			case "environment_error":
				env := Document(d["environment_metadata"])
				env["error_present"] = true
				d["environment_metadata"] = env
			case "missing_full_get":
				d["native_configuration_response_observed"] = false
			case "missing_native_field":
				p := Document(d["native_field_presence"])
				p["Layers"] = false
				d["native_field_presence"] = p
			case "filesystem":
				d["file_systems"] = []model.Document{{"Arn": "arn:external-filesystem"}}
			case "provisioned":
				d["provisioned_concurrency"] = []model.Document{{"AllocatedProvisionedConcurrentExecutions": 1}}
			case "weighted":
				d["routing_weights"] = model.Document{"2": "0.1"}
			}
			if fp, rs := NonMemoryFingerprint(d); fp != "" || len(rs) == 0 {
				t.Fatal("unknown configuration became comparable")
			}
		})
	}
}
func TestLambdaNonMemoryFingerprintOnlyPermitsMemoryAndVersionIdentityChanges(t *testing.T) {
	c := nativeComparableTestConfig()
	baseline, _ := NonMemoryFingerprint(c)
	c["memory_size_mb"], c["version"], c["qualified_arn"], c["configuration_epoch_hash"] = 1536, "2", "arn:other-version", Hash("candidate-epoch")
	got, rs := NonMemoryFingerprint(c)
	if got != baseline || len(rs) > 0 {
		t.Fatal("permitted memory comparison changed", rs)
	}
	for _, key := range []string{"runtime", "handler", "architecture", "code_sha256", "execution_role_metadata"} {
		d := Document(c)
		d[key] = "different"
		fp, rs := NonMemoryFingerprint(d)
		if len(rs) == 0 && fp == baseline {
			t.Fatal("non-memory difference accepted", key)
		}
	}
	d := Document(c)
	d["layers"] = []model.Document{{"Arn": "first:1"}, {"Arn": "second:1"}}
	first, _ := NonMemoryFingerprint(d)
	d["layers"] = []model.Document{{"Arn": "second:1"}, {"Arn": "first:1"}}
	second, _ := NonMemoryFingerprint(d)
	if first == second {
		t.Fatal("layer merge order was discarded")
	}
}
