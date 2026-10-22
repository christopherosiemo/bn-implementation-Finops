package source

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"sort"
	"strings"
)

type controllerXMLAttribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type controllerXMLValue struct {
	Name       string                   `json:"name"`
	Attributes []controllerXMLAttribute `json:"attributes"`
	Text       string                   `json:"text"`
	Children   []controllerXMLValue     `json:"children"`
}

func controllerXMLName(name xml.Name) string { return name.Space + "|" + name.Local }

// Called only AFTER the production signed-query frame replay has authenticated
// the account/selectors and exact typed/raw projection. Keep complete native
// XML, including fields FleetGroup does not model. Only exact protocol request
// identifiers and pagination tokens are transport provenance. There is no
// recursive deletion of similarly named native configuration fields.
func controllerDiscoveryNativeGraph(raw []byte) (string, error) {
	if len(raw) == 0 || len(raw) > 32<<20 {
		return "", errors.New("CONTROLLER_DISCOVERY_NATIVE_GRAPH_INVALID")
	}
	reader := bytes.NewReader(raw)
	pages := []json.RawMessage{}
	for reader.Len() > 0 {
		var selectorSize uint32
		var bodySize uint64
		if binary.Read(reader, binary.BigEndian, &selectorSize) != nil || selectorSize == 0 || selectorSize > 64<<10 || uint64(selectorSize) > uint64(reader.Len()) {
			return "", errors.New("CONTROLLER_DISCOVERY_NATIVE_GRAPH_INVALID")
		}
		selector := make([]byte, int(selectorSize))
		if _, e := io.ReadFull(reader, selector); e != nil {
			return "", errors.New("CONTROLLER_DISCOVERY_NATIVE_GRAPH_INVALID")
		}
		values, e := url.ParseQuery(string(selector))
		if e != nil || values.Encode() != string(selector) {
			return "", errors.New("CONTROLLER_DISCOVERY_NATIVE_GRAPH_INVALID")
		}
		if binary.Read(reader, binary.BigEndian, &bodySize) != nil || bodySize == 0 || bodySize > 16<<20 || bodySize > uint64(reader.Len()) {
			return "", errors.New("CONTROLLER_DISCOVERY_NATIVE_GRAPH_INVALID")
		}
		body := make([]byte, int(bodySize))
		if _, e = io.ReadFull(reader, body); e != nil {
			return "", errors.New("CONTROLLER_DISCOVERY_NATIVE_GRAPH_INVALID")
		}
		action := values.Get("Action")
		if action == "GetCallerIdentity" {
			continue
		}
		if action != "DescribeAutoScalingInstances" && action != "DescribeAutoScalingGroups" {
			return "", errors.New("CONTROLLER_DISCOVERY_NATIVE_GRAPH_INVALID")
		}
		value, e := controllerNativeXML(body, action)
		if e != nil {
			return "", e
		}
		values.Del("NextToken")
		page, e := json.Marshal(struct {
			Selector string             `json:"selector"`
			Native   controllerXMLValue `json:"native"`
		}{values.Encode(), value})
		if e != nil {
			return "", e
		}
		pages = append(pages, page)
		if len(pages) > 100 {
			return "", errors.New("CONTROLLER_DISCOVERY_NATIVE_GRAPH_INVALID")
		}
	}
	if len(pages) < 1 {
		return "", errors.New("CONTROLLER_DISCOVERY_NATIVE_GRAPH_INVALID")
	}
	sort.Slice(pages, func(i, j int) bool { return bytes.Compare(pages[i], pages[j]) < 0 })
	return Hash(pages), nil
}

func controllerNativeXML(raw []byte, action string) (controllerXMLValue, error) {
	empty := controllerXMLValue{}
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	stack := []controllerXMLValue{}
	path := []string{}
	var root controllerXMLValue
	roots, nodes := 0, 0
	for {
		token, e := decoder.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return empty, errors.New("CONTROLLER_DISCOVERY_NATIVE_GRAPH_INVALID")
		}
		switch value := token.(type) {
		case xml.StartElement:
			nodes++
			if nodes > 200000 || len(stack) >= 64 {
				return empty, errors.New("CONTROLLER_DISCOVERY_NATIVE_GRAPH_INVALID")
			}
			node := controllerXMLValue{Name: controllerXMLName(value.Name), Attributes: []controllerXMLAttribute{}, Children: []controllerXMLValue{}}
			for _, attribute := range value.Attr {
				node.Attributes = append(node.Attributes, controllerXMLAttribute{controllerXMLName(attribute.Name), attribute.Value})
			}
			sort.Slice(node.Attributes, func(i, j int) bool {
				if node.Attributes[i].Name != node.Attributes[j].Name {
					return node.Attributes[i].Name < node.Attributes[j].Name
				}
				return node.Attributes[i].Value < node.Attributes[j].Value
			})
			stack = append(stack, node)
			path = append(path, value.Name.Local)
		case xml.CharData:
			if len(stack) == 0 {
				if strings.TrimSpace(string(value)) != "" {
					return empty, errors.New("CONTROLLER_DISCOVERY_NATIVE_GRAPH_INVALID")
				}
			} else {
				stack[len(stack)-1].Text += string(value)
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return empty, errors.New("CONTROLLER_DISCOVERY_NATIVE_GRAPH_INVALID")
			}
			node := stack[len(stack)-1]
			depth := len(path)
			drop := depth == 3 && path[0] == action+"Response" && ((path[1] == "ResponseMetadata" && path[2] == "RequestId") || (path[1] == action+"Result" && path[2] == "NextToken"))
			if len(node.Children) > 0 {
				if strings.TrimSpace(node.Text) != "" {
					return empty, errors.New("CONTROLLER_DISCOVERY_NATIVE_GRAPH_INVALID")
				}
				node.Text = ""
			}
			if depth == 2 && path[0] == action+"Response" && path[1] == "ResponseMetadata" && len(node.Children) == 0 && strings.TrimSpace(node.Text) == "" && len(node.Attributes) == 0 {
				drop = true
			}
			stack = stack[:len(stack)-1]
			path = path[:len(path)-1]
			if !drop {
				if len(stack) == 0 {
					roots++
					root = node
				} else {
					stack[len(stack)-1].Children = append(stack[len(stack)-1].Children, node)
				}
			}
		case xml.Directive:
			return empty, errors.New("CONTROLLER_DISCOVERY_NATIVE_GRAPH_INVALID")
		}
	}
	if roots != 1 || len(stack) != 0 || root.Name != "|"+action+"Response" && !strings.HasSuffix(root.Name, "|"+action+"Response") {
		return empty, errors.New("CONTROLLER_DISCOVERY_NATIVE_GRAPH_INVALID")
	}
	return root, nil
}
