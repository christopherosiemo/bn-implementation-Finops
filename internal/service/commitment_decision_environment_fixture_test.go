package service

import (
	"errors"
	"os"
	"testing"
)

// Preserve both the value and presence of these process-local fixture keys.
// Restore immediately at the enclosing function's deferred boundary. Using
// t.Setenv here would create another test-end cleanup and turn absence into
// present-empty in the meantime. The fixture's original t.Setenv cleanups
// remain responsible for their own ordinary test-end restoration.
func commitmentDecisionPreserveEnvironment(t testing.TB, keys ...string) func() {
	t.Helper()
	type entry struct {
		key, value string
		present    bool
	}
	saved := make([]entry, 0, len(keys))
	for _, key := range keys {
		value, present := os.LookupEnv(key)
		saved = append(saved, entry{key: key, value: value, present: present})
	}
	return func() {
		t.Helper()
		for _, old := range saved {
			var err error
			if old.present {
				err = os.Setenv(old.key, old.value)
			} else {
				err = os.Unsetenv(old.key)
			}
			if err != nil {
				t.Errorf("restore fixture environment key %q: %v", old.key, err)
			}
		}
	}
}

func TestCommitmentDecisionFixtureEnvironmentPreservesPresence(t *testing.T) {
	const key = "COMMITMENT_DECISION_TEST_ENV_PRESENCE"
	for _, tc := range []struct {
		name, value string
		present     bool
	}{{"absent", "", false}, {"present_empty", "", true}, {"present_value", "original-fixture-value", true}} {
		t.Run(tc.name, func(t *testing.T) {
			// The outer cleanup protects the real process even for the absent case.
			t.Setenv(key, tc.value)
			if !tc.present {
				if err := os.Unsetenv(key); err != nil {
					t.Fatal(err)
				}
			}
			restore := commitmentDecisionPreserveEnvironment(t, key)
			t.Setenv(key, "temporary-provider-fixture")
			restore()
			value, present := os.LookupEnv(key)
			if value != tc.value || present != tc.present {
				t.Fatal("fixture restore changed original environment presence/value")
			}
		})
	}
}

func TestCommitmentDecisionFixtureEnvironmentRestoresOnEarlyReturn(t *testing.T) {
	const key = "COMMITMENT_DECISION_TEST_ENV_RETURN"
	t.Setenv(key, "")
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
	err := func() error {
		restore := commitmentDecisionPreserveEnvironment(t, key)
		defer restore()
		t.Setenv(key, "temporary-provider-fixture")
		return errors.New("explicit fixture early return")
	}()
	if err == nil {
		t.Fatal("early return was not exercised")
	}
	if _, present := os.LookupEnv(key); present {
		t.Fatal("originally absent variable remained present after return")
	}
}

func TestCommitmentDecisionFixtureEnvironmentKeepsCleanupAndOtherKeys(t *testing.T) {
	const key = "COMMITMENT_DECISION_TEST_ENV_CLEANUP"
	const other = "COMMITMENT_DECISION_TEST_ENV_UNRELATED"
	t.Setenv(key, "original-fixture-value")
	t.Setenv(other, "original-unrelated")
	t.Run("provider_fixture", func(t *testing.T) {
		restore := commitmentDecisionPreserveEnvironment(t, key)
		defer restore()
		t.Setenv(key, "temporary-provider-fixture")
		// This variable is outside the snapshot. Its ordinary test cleanup still
		// owns it; the preservation helper must not restore the whole environment.
		t.Setenv(other, "changed-unrelated")
		restore()
		if os.Getenv(other) != "changed-unrelated" {
			t.Fatal("fixture restoration changed an unrelated variable")
		}
	})
	value, present := os.LookupEnv(key)
	if !present || value != "original-fixture-value" || os.Getenv(other) != "original-unrelated" {
		t.Fatal("ordinary test cleanup and immediate restoration disagreed")
	}
}
