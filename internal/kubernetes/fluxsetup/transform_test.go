package fluxsetup

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func deployment(name, image string) map[string]any {
	return map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": name, "namespace": Namespace},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"serviceAccountName": name,
			"containers": []any{map[string]any{
				"name": "manager", "image": image,
				"args":      []any{"--watch-all-namespaces=false", "--log-level=info"},
				"resources": map[string]any{"requests": map[string]any{"cpu": "100m", "memory": "64Mi"}},
			}},
		}}},
	}
}

func binding(name, role string) map[string]any {
	return map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
		"metadata": map[string]any{"name": name},
		"roleRef":  map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": role},
		"subjects": []any{map[string]any{"kind": "ServiceAccount", "name": "kustomize-controller", "namespace": Namespace}},
	}
}

func fixtureObjects() []map[string]any {
	return []map[string]any{
		{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": Namespace}},
		{"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition", "metadata": map[string]any{"name": "gitrepositories.source.toolkit.fluxcd.io"}, "spec": map[string]any{
			"group": "source.toolkit.fluxcd.io", "scope": "Namespaced",
			"versions": []any{map[string]any{"name": "v1", "served": true, "storage": true, "schema": map[string]any{"openAPIV3Schema": map[string]any{"type": "object", "x-kubernetes-preserve-unknown-fields": true}}}},
		}},
		{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": map[string]any{"name": "crd-controller-" + Namespace}, "rules": []any{map[string]any{"apiGroups": []any{"source.toolkit.fluxcd.io"}, "verbs": []any{"get", "list", "watch"}, "resources": []any{"*"}}}},
		binding("cluster-reconciler-"+Namespace, "cluster-admin"),
		binding("another-cluster-admin", "cluster-admin"),
		binding("crd-controller-"+Namespace, "crd-controller-"+Namespace),
		deployment("source-controller", SourceImage),
		deployment("kustomize-controller", KustomizeImage),
	}
}

func stream(t *testing.T, objects []map[string]any) []byte {
	t.Helper()
	var output bytes.Buffer
	for _, object := range objects {
		data, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		output.Write(data)
		output.WriteString("\n---\n")
	}
	return output.Bytes()
}

func outputItems(t *testing.T, output []byte) []map[string]any {
	t.Helper()
	var list struct {
		APIVersion string           `json:"apiVersion"`
		Kind       string           `json:"kind"`
		Items      []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(output, &list); err != nil {
		t.Fatal(err)
	}
	if list.APIVersion != "v1" || list.Kind != "List" {
		t.Fatalf("unexpected list envelope: %s", output)
	}
	return list.Items
}

func manager(object map[string]any) map[string]any {
	return object["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
}

func TestTransformPinsControllersPreservesCRDsAndRBACRemovesAllClusterAdmin(t *testing.T) {
	objects := fixtureObjects()
	input := stream(t, objects)
	before := append([]byte(nil), input...)
	output, err := Transform(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, before) {
		t.Fatal("input bytes were mutated")
	}
	items := outputItems(t, output)
	if len(items) != len(objects)-2 {
		t.Fatalf("output object count = %d", len(items))
	}
	for _, item := range items {
		kind := item["kind"].(string)
		name := item["metadata"].(map[string]any)["name"].(string)
		if kind == "ClusterRoleBinding" && item["roleRef"].(map[string]any)["name"] == "cluster-admin" {
			t.Fatal("cluster-admin binding survived")
		}
		if kind == "Deployment" {
			container := manager(item)
			if container["imagePullPolicy"] != "Never" {
				t.Fatal("fixture controller can fetch an unprepared runtime image")
			}
			want := SourcePinnedImage
			if name == "kustomize-controller" {
				want = KustomizePinnedImage
			}
			if container["image"] != want {
				t.Fatalf("controller %s image = %v", name, container["image"])
			}
			resources := container["resources"].(map[string]any)
			if !reflect.DeepEqual(resources["requests"], map[string]any{"cpu": "50m", "memory": "128Mi"}) || !reflect.DeepEqual(resources["limits"], map[string]any{"cpu": "500m", "memory": "384Mi"}) {
				t.Fatalf("unexpected fixture resources: %#v", resources)
			}
			args := container["args"].([]any)
			if name == "kustomize-controller" {
				for _, required := range []string{"--watch-all-namespaces=false", "--no-cross-namespace-refs=true", "--no-remote-bases=true", "--default-service-account=default", "--log-level=info"} {
					count := 0
					for _, arg := range args {
						if arg == required {
							count++
						}
					}
					if count != 1 {
						t.Fatalf("argument %s count = %d", required, count)
					}
				}
			} else if !reflect.DeepEqual(args, []any{"--watch-all-namespaces=false", "--log-level=info"}) {
				t.Fatalf("source arguments changed: %#v", args)
			}
		} else {
			var original map[string]any
			for _, object := range objects {
				if object["kind"] == kind && object["metadata"].(map[string]any)["name"] == name {
					original = object
					break
				}
			}
			if !reflect.DeepEqual(item, original) {
				t.Fatalf("official %s %s was modified", kind, name)
			}
		}
	}
	second, err := Transform(before)
	if err != nil || !bytes.Equal(second, output) {
		t.Fatal("transform is not deterministic")
	}
}

func TestTransformReplacesConflictingIsolationArgs(t *testing.T) {
	objects := fixtureObjects()
	manager(objects[7])["args"] = []any{
		"--watch-all-namespaces=false", "--log-level=debug",
		"--no-cross-namespace-refs=false", "--no-cross-namespace-refs", "false",
		"--no-remote-bases", "--default-service-account", "elevated",
		"--default-service-account=another",
	}
	output, err := Transform(stream(t, objects))
	if err != nil {
		t.Fatal(err)
	}
	items := outputItems(t, output)
	got := manager(items[len(items)-1])["args"]
	want := []any{"--watch-all-namespaces=false", "--log-level=debug", "--no-cross-namespace-refs=true", "--no-remote-bases=true", "--default-service-account=default"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("isolation args = %#v, want %#v", got, want)
	}
}

func TestTransformRejectsUnexpectedControllersVersionsNamespacesAndScopes(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func([]map[string]any) []map[string]any
	}{
		{"wrong-source-version", func(o []map[string]any) []map[string]any {
			manager(o[6])["image"] = "ghcr.io/fluxcd/source-controller:v1.9.5"
			return o
		}},
		{"wrong-kustomize-version", func(o []map[string]any) []map[string]any {
			manager(o[7])["image"] = "ghcr.io/fluxcd/kustomize-controller:latest"
			return o
		}},
		{"already-pinned-unexpected-input", func(o []map[string]any) []map[string]any { manager(o[6])["image"] = SourcePinnedImage; return o }},
		{"third-controller", func(o []map[string]any) []map[string]any {
			return append(o, deployment("helm-controller", "ghcr.io/fluxcd/helm-controller:v1.9.6"))
		}},
		{"missing-controller", func(o []map[string]any) []map[string]any { return o[:7] }},
		{"duplicate-controller", func(o []map[string]any) []map[string]any {
			return append(o, deployment("source-controller", SourceImage))
		}},
		{"sidecar", func(o []map[string]any) []map[string]any {
			p := o[6]["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
			p["containers"] = append(p["containers"].([]any), map[string]any{"name": "sidecar", "image": "unknown"})
			return o
		}},
		{"init-container", func(o []map[string]any) []map[string]any {
			o[6]["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["initContainers"] = []any{map[string]any{"name": "init", "image": "unknown"}}
			return o
		}},
		{"namespace", func(o []map[string]any) []map[string]any {
			o[0]["metadata"].(map[string]any)["name"] = "flux-system"
			return o
		}},
		{"missing-namespace", func(o []map[string]any) []map[string]any { return o[1:] }},
		{"deployment-namespace", func(o []map[string]any) []map[string]any {
			o[6]["metadata"].(map[string]any)["namespace"] = "default"
			return o
		}},
		{"missing-deployment-namespace", func(o []map[string]any) []map[string]any {
			delete(o[6]["metadata"].(map[string]any), "namespace")
			return o
		}},
		{"cluster-role-namespace", func(o []map[string]any) []map[string]any {
			o[2]["metadata"].(map[string]any)["namespace"] = Namespace
			return o
		}},
		{"binding-subject-namespace", func(o []map[string]any) []map[string]any {
			o[3]["subjects"].([]any)[0].(map[string]any)["namespace"] = "default"
			return o
		}},
		{"watch-all", func(o []map[string]any) []map[string]any {
			manager(o[7])["args"] = []any{"--watch-all-namespaces=true"}
			return o
		}},
		{"watch-missing", func(o []map[string]any) []map[string]any { manager(o[7])["args"] = []any{"--log-level=info"}; return o }},
		{"watch-duplicate", func(o []map[string]any) []map[string]any {
			manager(o[7])["args"] = []any{"--watch-all-namespaces=false", "--watch-all-namespaces=false"}
			return o
		}},
		{"watch-split", func(o []map[string]any) []map[string]any {
			manager(o[7])["args"] = []any{"--watch-all-namespaces", "false"}
			return o
		}},
		{"non-string-arg", func(o []map[string]any) []map[string]any { manager(o[7])["args"] = []any{false}; return o }},
		{"default-service-account-missing-value", func(o []map[string]any) []map[string]any {
			manager(o[7])["args"] = []any{"--watch-all-namespaces=false", "--default-service-account"}
			return o
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			output, err := Transform(stream(t, test.mutate(fixtureObjects())))
			if err == nil || len(output) != 0 {
				t.Fatalf("invalid fixture accepted: %s, %v", output, err)
			}
		})
	}
}

func TestTransformYAMLStreamPreservesCRDSchemaScalars(t *testing.T) {
	input := stream(t, fixtureObjects())
	input = append(input, []byte(`apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: synthetic.example.invalid
spec:
  versions:
    - name: v1
      served: true
      storage: false
      schema:
        openAPIV3Schema:
          type: object
          properties:
            count:
              type: integer
              minimum: 0
              maximum: 9007199254740993
            text:
              type: string
              default: "true"
              description: |
                Non-ASCII Ω, quoted "value", and <>& remain strings.
          nullable: null
`)...)
	output, err := Transform(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output, []byte(`9007199254740993`)) || !bytes.Contains(output, []byte(`"default":"true"`)) || !bytes.Contains(output, []byte(`"nullable":null`)) {
		t.Fatalf("schema scalar types were changed: %s", output)
	}
}

func TestTransformRejectsMalformedOrUnboundedYAML(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"oversized", bytes.Repeat([]byte(" "), MaxInputBytes+1)},
		{"array", []byte("[1,2]\n")},
		{"duplicate-key", []byte("kind: Namespace\nkind: Namespace\n")},
		{"alias", []byte("a: &anchor {}\nb: *anchor\n")},
		{"custom-tag", []byte("a: !custom value\n")},
		{"non-json-number", []byte("a: .inf\n")},
		{"non-string-key", []byte("1: value\n")},
		{"nested", []byte("a: " + strings.Repeat("[", 82) + "null" + strings.Repeat("]", 82) + "\n")},
		{"many-documents", []byte(strings.Repeat("---\n#empty\n", 513))},
		{"invalid-yaml", []byte("a: [unterminated\n")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if output, err := Transform(test.data); err == nil || len(output) != 0 {
				t.Fatalf("invalid YAML accepted: %s, %v", output, err)
			}
		})
	}
}
