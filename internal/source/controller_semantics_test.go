package source

import (
	"bytes"
	"encoding/binary"
	"net/url"
	"strings"
	"testing"
)

func controllerGraphTestFrame(selector url.Values, body string) []byte {
	var raw bytes.Buffer
	encoded := selector.Encode()
	_ = binary.Write(&raw, binary.BigEndian, uint32(len(encoded)))
	raw.WriteString(encoded)
	_ = binary.Write(&raw, binary.BigEndian, uint64(len(body)))
	raw.WriteString(body)
	return raw.Bytes()
}

func TestControllerGraphRetainsUnprojectedNativeFieldsAndIgnoresExactTransportMetadata(t *testing.T) {
	selector := url.Values{"Action": {"DescribeAutoScalingGroups"}, "Version": {"2011-01-01"}, "AutoScalingGroupNames.member.1": {"fixed"}, "IncludeInstances": {"true"}, "MaxRecords": {"100"}}
	native := `<DescribeAutoScalingGroupsResponse><DescribeAutoScalingGroupsResult><AutoScalingGroups><member><AutoScalingGroupName>fixed</AutoScalingGroupName><MinSize>1</MinSize><MaxSize>1</MaxSize><DesiredCapacity>1</DesiredCapacity><HealthCheckGracePeriod>300</HealthCheckGracePeriod><MixedInstancesPolicy><InstancesDistribution><OnDemandPercentageAboveBaseCapacity>25</OnDemandPercentageAboveBaseCapacity></InstancesDistribution></MixedInstancesPolicy><Tags><member><Key>RequestId</Key><Value>actual-native-tag</Value></member></Tags></member></AutoScalingGroups><NextToken>page-A</NextToken></DescribeAutoScalingGroupsResult><ResponseMetadata><RequestId>request-A</RequestId></ResponseMetadata></DescribeAutoScalingGroupsResponse>`
	original, e := controllerDiscoveryNativeGraph(controllerGraphTestFrame(selector, native))
	if e != nil {
		t.Fatal(e)
	}
	changedTransport := strings.ReplaceAll(strings.ReplaceAll(native, "request-A", "request-B"), "page-A", "page-B")
	selector.Set("NextToken", "previous-B")
	same, e := controllerDiscoveryNativeGraph(controllerGraphTestFrame(selector, changedTransport))
	if e != nil || same != original {
		t.Fatal("protocol transport-only change altered native graph", e)
	}
	negatives := []struct{ name, old, new string }{
		{"unprojected-grace", "<HealthCheckGracePeriod>300</HealthCheckGracePeriod>", "<HealthCheckGracePeriod>301</HealthCheckGracePeriod>"},
		{"unprojected-mixed-policy", ">25</OnDemandPercentageAboveBaseCapacity>", ">26</OnDemandPercentageAboveBaseCapacity>"},
		{"native-requestid-tag", "actual-native-tag", "changed-native-tag"},
		{"native-minimum", "<MinSize>1</MinSize>", "<MinSize>2</MinSize>"},
	}
	for _, test := range negatives {
		t.Run(test.name, func(t *testing.T) {
			value, e := controllerDiscoveryNativeGraph(controllerGraphTestFrame(selector, strings.Replace(changedTransport, test.old, test.new, 1)))
			if e != nil || value == original {
				t.Fatal("actual native change disappeared from complete XML graph", e)
			}
		})
	}
	// A similarly named nested native element is not protocol metadata.
	nested := strings.Replace(changedTransport, "<HealthCheckGracePeriod>300</HealthCheckGracePeriod>", "<NativeConstraint><RequestId>one</RequestId><NextToken>one</NextToken></NativeConstraint>", 1)
	one, e := controllerDiscoveryNativeGraph(controllerGraphTestFrame(selector, nested))
	if e != nil {
		t.Fatal(e)
	}
	two, e := controllerDiscoveryNativeGraph(controllerGraphTestFrame(selector, strings.Replace(nested, "<RequestId>one</RequestId>", "<RequestId>two</RequestId>", 1)))
	if e != nil || one == two {
		t.Fatal("recursive RequestId deletion hid native configuration", e)
	}
	two, e = controllerDiscoveryNativeGraph(controllerGraphTestFrame(selector, strings.Replace(nested, "<NextToken>one</NextToken>", "<NextToken>two</NextToken>", 1)))
	if e != nil || one == two {
		t.Fatal("recursive NextToken deletion hid native configuration", e)
	}
}
