package commitmentportfolio

import "strings"

// CUR keeps the native ARN. Only a complete exact ARN tied to an actually
// selected DescribeReservedInstances identity acquires that point's local key.
// Shared covered-usage accounts are separately checked against issued scope.
func selectedCommitmentIdentity(native string, positions []Position) string {
	if !strings.HasPrefix(native, "arn:aws:ec2:") {
		return native
	}
	for _, position := range positions {
		if position.ReservedInstanceTerms == nil || position.Region == nil || !strings.HasPrefix(position.ID, position.AccountID+":ri:") {
			continue
		}
		id := strings.TrimPrefix(position.ID, position.AccountID+":ri:")
		if id == "" || strings.ContainsAny(id, ":/") {
			continue
		}
		expected := "arn:aws:ec2:" + *position.Region + ":" + position.AccountID + ":reserved-instances/" + id
		if native == expected {
			return position.ID
		}
	}
	return native
}
