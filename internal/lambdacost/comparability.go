package lambdacost

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

const NonMemoryConfigurationVersion = "LAMBDA_NON_MEMORY_CONFIG_V1"

// NonMemoryFingerprint compares only explicitly observed ordinary Zip function
// configuration. Memory, published-version identity and revision timestamps are
// deliberately separate. Missing optional structures never become empty proof.
func NonMemoryFingerprint(c model.Document) (string, []string) {
	reasons := []string{}
	if c["native_configuration_response_observed"] != true {
		reasons = append(reasons, "LAMBDA_FULL_NATIVE_CONFIGURATION_RESPONSE_REQUIRED")
	}
	presence := Document(c["native_field_presence"])
	for _, key := range []string{"FunctionArn", "Version", "CodeSha256", "Runtime", "Handler", "PackageType", "Architectures", "Timeout", "EphemeralStorage", "VpcConfig", "Layers", "FileSystemConfigs", "Environment", "RuntimeVersionConfig", "Role", "TracingConfig", "DeadLetterConfig", "LoggingConfig", "SnapStart"} {
		if presence[key] != true {
			reasons = append(reasons, "LAMBDA_NON_MEMORY_FIELD_"+strings.ToUpper(key)+"_UNOBSERVED")
		}
	}
	if c["package_type"] != "Zip" || c["model"] != "EVENT_DEFAULT" {
		reasons = append(reasons, "LAMBDA_NON_MEMORY_MODEL_UNSUPPORTED")
	}
	if c["multiple_serving_versions"] == true || len(Document(c["routing_weights"])) > 0 {
		reasons = append(reasons, "LAMBDA_WEIGHTED_SERVING_CONFIGURATION_REQUIRES_SEPARATE_COHORTS")
	}
	fields := model.Document{"definition_version": NonMemoryConfigurationVersion}
	for _, key := range []string{"base_function_arn", "code_sha256", "runtime", "handler", "package_type", "architecture", "execution_role_metadata"} {
		value := model.String(c, key)
		if value == "" {
			reasons = append(reasons, "LAMBDA_NON_MEMORY_"+strings.ToUpper(key)+"_UNKNOWN")
		}
		fields[key] = value
	}
	runtime := Document(c["runtime_version"])
	if model.String(runtime, "RuntimeVersionArn") == "" {
		reasons = append(reasons, "LAMBDA_MANAGED_RUNTIME_VERSION_UNKNOWN")
	}
	if len(Document(runtime["Error"])) > 0 {
		reasons = append(reasons, "LAMBDA_MANAGED_RUNTIME_VERSION_ERROR")
	}
	fields["runtime_version_arn"] = runtime["RuntimeVersionArn"]
	for _, key := range []string{"timeout_seconds", "ephemeral_storage_mb"} {
		value, err := strconv.ParseInt(fmt.Sprint(c[key]), 10, 64)
		if err != nil || value <= 0 {
			reasons = append(reasons, "LAMBDA_NON_MEMORY_"+strings.ToUpper(key)+"_UNKNOWN")
		}
		fields[key] = strconv.FormatInt(value, 10)
	}
	environment := Document(c["environment_metadata"])
	if environment["present"] != true || environment["variables_observed"] != true || environment["error_present"] != false || environment["values_redacted"] != true || model.Number(environment, "variable_count") != 0 || model.String(environment, "error_code") != "" {
		reasons = append(reasons, "LAMBDA_POSITIVELY_EMPTY_ENVIRONMENT_REQUIRED")
	}
	fields["environment"] = "EXPLICIT_EMPTY_VARIABLE_MAP_NO_ERROR"
	pc, pcKnown := configurationObjectArray(c["provisioned_concurrency"])
	if !pcKnown || len(pc) > 0 {
		reasons = append(reasons, "LAMBDA_PROVISIONED_BENCHMARK_SERVING_CONTEXT_UNPROVEN")
	}
	fields["provisioned_concurrency"] = "EXPLICIT_EMPTY"
	reserved, reservedError := strconv.ParseInt(fmt.Sprint(c["reserved_concurrency"]), 10, 64)
	if reservedError != nil || reserved < 0 {
		reasons = append(reasons, "LAMBDA_RESERVED_BENCHMARK_SERVING_CONTEXT_UNPROVEN")
	}
	fields["reserved_concurrency"] = strconv.FormatInt(reserved, 10)
	vpc := Document(c["vpc"])
	normalizedVPC := model.Document{}
	for _, key := range []string{"VpcId", "SubnetIds", "SecurityGroupIds", "Ipv6AllowedForDualStack"} {
		if _, exists := vpc[key]; !exists {
			reasons = append(reasons, "LAMBDA_VPC_CONFIGURATION_INCOMPLETE")
		}
	}
	normalizedVPC["VpcId"] = vpc["VpcId"]
	normalizedVPC["Ipv6AllowedForDualStack"] = vpc["Ipv6AllowedForDualStack"]
	for _, key := range []string{"SubnetIds", "SecurityGroupIds"} {
		values, known := configurationStringArray(vpc[key])
		if !known {
			reasons = append(reasons, "LAMBDA_VPC_CONFIGURATION_INCOMPLETE")
		}
		sort.Strings(values)
		normalizedVPC[key] = values
	}
	fields["vpc"] = normalizedVPC
	layers, known := configurationObjectArray(c["layers"])
	if !known {
		reasons = append(reasons, "LAMBDA_LAYER_DEPENDENCY_METADATA_UNKNOWN")
	}
	layerRefs := []string{}
	for _, layer := range layers {
		arn := model.String(layer, "Arn")
		if arn == "" {
			reasons = append(reasons, "LAMBDA_LAYER_VERSION_UNKNOWN")
		}
		layerRefs = append(layerRefs, arn)
	}
	fields["layers"] = layerRefs
	filesystems, known := configurationObjectArray(c["file_systems"])
	if !known || len(filesystems) > 0 {
		reasons = append(reasons, "LAMBDA_FILESYSTEM_DEPENDENCY_CONTENT_UNPROVEN")
	}
	fields["filesystems"] = "EXPLICIT_EMPTY"
	for _, key := range []string{"tracing", "dead_letter", "logging", "snap_start"} {
		if c[key] == nil {
			reasons = append(reasons, "LAMBDA_NON_MEMORY_"+strings.ToUpper(key)+"_UNOBSERVED")
		}
		fields[key] = c[key]
	}
	for _, key := range []string{"capacity_provider", "durable_configuration", "tenancy_configuration"} {
		if len(Document(c[key])) > 0 {
			reasons = append(reasons, "LAMBDA_NON_MEMORY_MODEL_UNSUPPORTED")
		}
	}
	sort.Strings(reasons)
	if len(reasons) > 0 {
		return "", reasons
	}
	return Hash(fields), nil
}
func configurationStringArray(value any) ([]string, bool) {
	switch v := value.(type) {
	case []string:
		return append([]string{}, v...), true
	case []any:
		out := []string{}
		for _, x := range v {
			s, ok := x.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}
func configurationObjectArray(value any) ([]model.Document, bool) {
	switch v := value.(type) {
	case []model.Document:
		return append([]model.Document{}, v...), true
	case []any:
		out := []model.Document{}
		for _, x := range v {
			switch x.(type) {
			case map[string]any, model.Document:
				out = append(out, Document(x))
			default:
				return nil, false
			}
		}
		return out, true
	}
	return nil, false
}
