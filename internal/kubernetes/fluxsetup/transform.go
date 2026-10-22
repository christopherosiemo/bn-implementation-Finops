// Package fluxsetup prepares the pinned official Flux export for the isolated
// synthetic Kubernetes lab. It does not contact or mutate a cluster.
package fluxsetup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	Namespace            = "finops-flux-system"
	MaxInputBytes        = 1 << 20
	SourceImage          = "ghcr.io/fluxcd/source-controller:v1.9.6"
	KustomizeImage       = "ghcr.io/fluxcd/kustomize-controller:v1.9.6"
	SourcePinnedImage    = "ghcr.io/fluxcd/source-controller@sha256:d10ea2ebeb475de80a6d3caf792578b1eaaa0366c55442d20d7e5f6f78fad3ec"
	KustomizePinnedImage = "ghcr.io/fluxcd/kustomize-controller@sha256:cdab039ed285bfcac5605b92b2f0799c2bff24639b0dc4208671c7b3e828891a"
)

// Transform decodes a bounded YAML document stream from the pinned Flux CLI.
// It returns a JSON Kubernetes List with controller images pinned, fixture
// resource bounds, namespaced reconciliation flags, and no cluster-admin
// ClusterRoleBindings. Official CRDs and the remaining RBAC are preserved.
func Transform(input []byte) ([]byte, error) {
	if len(input) == 0 || len(input) > MaxInputBytes {
		return nil, errors.New("Flux export must contain between 1 and 1048576 bytes")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(input))
	items := make([]any, 0)
	seen := make(map[string]bool)
	controllers := make(map[string]bool)
	namespaceSeen := false
	nodes := 0
	for document := 0; ; document++ {
		if document >= 512 {
			return nil, errors.New("Flux export has too many documents")
		}
		var root yaml.Node
		if err := decoder.Decode(&root); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("invalid Flux YAML: %w", err)
		}
		if len(root.Content) == 0 {
			continue
		}
		if root.Content[0].Tag == "!!null" && root.Content[0].Value == "" {
			continue
		}
		value, err := jsonValue(root.Content[0], 0, &nodes)
		if err != nil {
			return nil, err
		}
		object, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("Flux export document must be an object")
		}
		apiVersion, ok := object["apiVersion"].(string)
		if !ok || apiVersion == "" {
			return nil, errors.New("Flux export object apiVersion missing")
		}
		kind, ok := object["kind"].(string)
		if !ok || !installKind(kind) {
			return nil, errors.New("Flux export contains an unsupported installation kind")
		}
		metadata, ok := object["metadata"].(map[string]any)
		if !ok {
			return nil, errors.New("Flux export object metadata missing")
		}
		name, ok := metadata["name"].(string)
		if !ok || name == "" {
			return nil, errors.New("Flux export object name missing")
		}
		namespace := ""
		if raw, exists := metadata["namespace"]; exists {
			namespace, ok = raw.(string)
			if !ok || namespace != Namespace {
				return nil, errors.New("Flux export contains an unexpected namespace")
			}
		}
		identity := apiVersion + "/" + kind + "/" + namespace + "/" + name
		if seen[identity] {
			return nil, errors.New("Flux export contains a duplicate object")
		}
		seen[identity] = true
		if kind == "Namespace" {
			if apiVersion != "v1" || name != Namespace || namespace != "" || namespaceSeen {
				return nil, errors.New("Flux export namespace does not match the local fixture")
			}
			namespaceSeen = true
		}
		if namespacedKind(kind) && namespace != Namespace {
			return nil, errors.New("Flux installation object must be in the fixture namespace")
		}
		if !namespacedKind(kind) && namespace != "" {
			return nil, errors.New("cluster-scoped Flux installation object has a namespace")
		}
		if kind == "RoleBinding" || kind == "ClusterRoleBinding" {
			if err := validateSubjects(object); err != nil {
				return nil, err
			}
			if kind == "ClusterRoleBinding" {
				role, ok := object["roleRef"].(map[string]any)
				if !ok || role["apiGroup"] != "rbac.authorization.k8s.io" || role["kind"] != "ClusterRole" {
					return nil, errors.New("invalid Flux ClusterRoleBinding roleRef")
				}
				if role["name"] == "cluster-admin" {
					continue
				}
			}
		}
		if kind == "Deployment" {
			if apiVersion != "apps/v1" || controllers[name] {
				return nil, errors.New("unexpected or duplicate Flux controller Deployment")
			}
			if err := prepareDeployment(object, name); err != nil {
				return nil, err
			}
			controllers[name] = true
		}
		items = append(items, object)
	}
	if !namespaceSeen || len(controllers) != 2 || !controllers["source-controller"] || !controllers["kustomize-controller"] {
		return nil, errors.New("Flux export must contain the fixture namespace and exactly source/kustomize controllers")
	}
	return json.Marshal(map[string]any{"apiVersion": "v1", "kind": "List", "items": items})
}

func installKind(kind string) bool {
	switch kind {
	case "Namespace", "CustomResourceDefinition", "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding", "ServiceAccount", "Service", "Deployment", "NetworkPolicy", "ResourceQuota", "PriorityClass":
		return true
	}
	return false
}

func namespacedKind(kind string) bool {
	switch kind {
	case "Role", "RoleBinding", "ServiceAccount", "Service", "Deployment", "NetworkPolicy", "ResourceQuota":
		return true
	}
	return false
}

func validateSubjects(object map[string]any) error {
	subjects, ok := object["subjects"].([]any)
	if !ok || len(subjects) == 0 {
		return errors.New("Flux role binding subjects missing")
	}
	for _, raw := range subjects {
		subject, ok := raw.(map[string]any)
		if !ok {
			return errors.New("invalid Flux role binding subject")
		}
		if namespace, exists := subject["namespace"]; exists && namespace != Namespace {
			return errors.New("Flux role binding subject has an unexpected namespace")
		}
		if subject["kind"] == "ServiceAccount" && subject["namespace"] != Namespace {
			return errors.New("Flux service account subject must be namespaced")
		}
	}
	return nil
}

func prepareDeployment(object map[string]any, name string) error {
	expected, pinned := "", ""
	switch name {
	case "source-controller":
		expected, pinned = SourceImage, SourcePinnedImage
	case "kustomize-controller":
		expected, pinned = KustomizeImage, KustomizePinnedImage
	default:
		return errors.New("unexpected third Flux controller")
	}
	spec, ok := object["spec"].(map[string]any)
	if !ok {
		return errors.New("Flux Deployment spec missing")
	}
	template, ok := spec["template"].(map[string]any)
	if !ok {
		return errors.New("Flux Deployment pod template missing")
	}
	pod, ok := template["spec"].(map[string]any)
	if !ok {
		return errors.New("Flux Deployment pod spec missing")
	}
	if init, exists := pod["initContainers"]; exists {
		list, ok := init.([]any)
		if !ok || len(list) != 0 {
			return errors.New("unexpected Flux init container")
		}
	}
	containers, ok := pod["containers"].([]any)
	if !ok || len(containers) != 1 {
		return errors.New("Flux Deployment must have exactly one manager container")
	}
	manager, ok := containers[0].(map[string]any)
	if !ok || manager["name"] != "manager" || manager["image"] != expected {
		return errors.New("Flux controller image or manager name does not match pinned CLI export")
	}
	args, ok := manager["args"].([]any)
	if !ok {
		return errors.New("Flux controller args missing")
	}
	stringsArgs := make([]string, len(args))
	watchCount := 0
	for i, raw := range args {
		argument, ok := raw.(string)
		if !ok {
			return errors.New("Flux controller argument is not a string")
		}
		if argument == "--watch-all-namespaces" || strings.HasPrefix(argument, "--watch-all-namespaces=") {
			if argument != "--watch-all-namespaces=false" {
				return errors.New("Flux controller must explicitly disable watching all namespaces")
			}
			watchCount++
		}
		stringsArgs[i] = argument
	}
	if watchCount != 1 {
		return errors.New("Flux controller must have one --watch-all-namespaces=false argument")
	}
	if name == "kustomize-controller" {
		var err error
		stringsArgs, err = isolationArgs(stringsArgs)
		if err != nil {
			return err
		}
	}
	newArgs := make([]any, len(stringsArgs))
	for i, argument := range stringsArgs {
		newArgs[i] = argument
	}
	manager["args"] = newArgs
	manager["image"] = pinned
	manager["imagePullPolicy"] = "Never" // Every exact manifest is preloaded and checked by the owned fixture.
	manager["resources"] = map[string]any{
		"requests": map[string]any{"cpu": "50m", "memory": "128Mi"},
		"limits":   map[string]any{"cpu": "500m", "memory": "384Mi"},
	}
	return nil
}

func isolationArgs(args []string) ([]string, error) {
	result := make([]string, 0, len(args)+3)
	for i := 0; i < len(args); i++ {
		argument := args[i]
		matched := false
		for _, flag := range []string{"--no-cross-namespace-refs", "--no-remote-bases", "--default-service-account"} {
			if argument != flag && !strings.HasPrefix(argument, flag+"=") {
				continue
			}
			matched = true
			if argument == flag {
				if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
					i++
				} else if flag == "--default-service-account" {
					return nil, errors.New("Flux default service account argument value missing")
				}
			}
			break
		}
		if !matched {
			result = append(result, argument)
		}
	}
	return append(result, "--no-cross-namespace-refs=true", "--no-remote-bases=true", "--default-service-account=default"), nil
}

func jsonValue(node *yaml.Node, depth int, nodes *int) (any, error) {
	*nodes++
	if depth > 80 || *nodes > 200000 || node.Anchor != "" || node.Kind == yaml.AliasNode {
		return nil, errors.New("Flux YAML exceeds shape bounds or contains aliases")
	}
	switch node.Kind {
	case yaml.MappingNode:
		if node.Tag != "!!map" || len(node.Content)%2 != 0 {
			return nil, errors.New("Flux YAML mapping is invalid")
		}
		object := make(map[string]any, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Anchor != "" {
				return nil, errors.New("Flux YAML object key must be a string")
			}
			if _, exists := object[key.Value]; exists {
				return nil, errors.New("Flux YAML contains a duplicate object key")
			}
			value, err := jsonValue(node.Content[i+1], depth+1, nodes)
			if err != nil {
				return nil, err
			}
			object[key.Value] = value
		}
		return object, nil
	case yaml.SequenceNode:
		if node.Tag != "!!seq" {
			return nil, errors.New("Flux YAML sequence has an unsupported tag")
		}
		array := make([]any, len(node.Content))
		for i, child := range node.Content {
			value, err := jsonValue(child, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			array[i] = value
		}
		return array, nil
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!str":
			return node.Value, nil
		case "!!null":
			return nil, nil
		case "!!bool":
			if node.Value == "true" || node.Value == "True" || node.Value == "TRUE" {
				return true, nil
			}
			if node.Value == "false" || node.Value == "False" || node.Value == "FALSE" {
				return false, nil
			}
		case "!!int", "!!float":
			if json.Valid([]byte(node.Value)) && node.Value != "null" && node.Value != "true" && node.Value != "false" && !strings.HasPrefix(node.Value, "\"") {
				return json.Number(node.Value), nil
			}
		}
	}
	return nil, errors.New("Flux YAML contains an unsupported value or tag")
}
