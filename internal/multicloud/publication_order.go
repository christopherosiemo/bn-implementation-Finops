package multicloud

import (
	"errors"
	"time"
)

// Native ordering never uses Snapshot.ObservedAt or publication completion time.
// GCP's validated FOR SYSTEM_TIME as_of binds the query snapshot. Azure has no
// comparable table timestamp: a completed run's native submittedTime orders
// runs. Same-run economic conflicts remain ambiguous rather than inferring a
// correction order from response arrival or a provider-opaque blob version ID.
func publicationNativeTime(r Registration, s Snapshot) (time.Time, error) {
	for _, o := range s.Objects {
		if r.GCP != nil && o.Kind == "GCP_QUERY_JOB_METADATA" {
			d, e := decode(o.Body)
			if e != nil {
				return time.Time{}, e
			}
			p, e := parameters(obj(obj(d["configuration"])["query"])["queryParameters"])
			if e != nil {
				return time.Time{}, e
			}
			at, e := instant(str(obj(p["as_of"]), "value"))
			if e != nil || at.IsZero() {
				return time.Time{}, errors.New("MULTICLOUD_NATIVE_ORDER_UNPROVEN")
			}
			return at.UTC(), nil
		}
		if r.Azure != nil && o.Kind == "AZURE_EXPORT_RUN_HISTORY" {
			d, e := decode(o.Body)
			if e != nil {
				return time.Time{}, e
			}
			for _, v := range list(d["value"]) {
				run := obj(v)
				if str(run, "id") == s.NativeReference {
					at, e := instant(str(obj(run["properties"]), "submittedTime"))
					if e != nil || at.IsZero() {
						return time.Time{}, errors.New("MULTICLOUD_NATIVE_ORDER_UNPROVEN")
					}
					return at.UTC(), nil
				}
			}
		}
	}
	return time.Time{}, errors.New("MULTICLOUD_NATIVE_ORDER_UNPROVEN")
}
