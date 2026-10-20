package commitmentarchive

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"

	portfolio "github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentportfolio"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
)

// Overlap raw transport only. Signature/interval/chain verification and guarded
// witness publication remain in their original order. At most four 64KiB
// objects are in flight, within the existing process and request limits.
const archiveObjectWindowSize = 4

var archiveSHA = regexp.MustCompile(`^[a-f0-9]{64}$`)

type archiveWindowObject struct {
	pin    portfolio.DecisionOwnershipArchiveObjectPin
	value  provider.BillingObject
	mirror model.Document
	cached bool
	err    error
}

type archiveObjectWindow struct {
	pins    []portfolio.DecisionOwnershipArchiveObjectPin
	index   map[string]int
	start   int
	active  int
	values  []archiveWindowObject
	binding string
	tenant  string
	source  string
	lookup  func(context.Context, portfolio.DecisionOwnershipArchiveRegistration, portfolio.DecisionOwnershipArchiveObjectPin) (provider.BillingObject, bool, error)
	read    func(context.Context, portfolio.DecisionOwnershipArchiveRegistration, portfolio.DecisionOwnershipArchiveObjectPin) (provider.BillingObject, error)
	write   func(context.Context, string, string, []byte) (model.Document, error)
}

func newArchiveObjectWindow(pins []portfolio.DecisionOwnershipArchiveObjectPin) (*archiveObjectWindow, error) {
	if len(pins) == 0 || len(pins) > 100000 {
		return nil, errors.New("OWNERSHIP_ARCHIVE_WINDOW_LIMIT")
	}
	w := &archiveObjectWindow{pins: pins, index: map[string]int{}, start: -1, active: -1}
	var total int64
	for i, p := range pins {
		key := p.Key + "\x00" + p.VersionID
		if _, duplicate := w.index[key]; duplicate || p.Key == "" || len(p.Key) > 2048 || strings.HasPrefix(p.Key, "/") || strings.Contains(p.Key, "..") || strings.Contains(p.Key, "//") || strings.ContainsAny(p.Key, "\\\x00\r\n") || p.VersionID == "" || p.VersionID == "null" || len(p.VersionID) > 1024 || !archiveSHA.MatchString(p.SHA256) || p.Bytes < 1 || p.Bytes > 64<<10 {
			return nil, errors.New("OWNERSHIP_ARCHIVE_WINDOW_SELECTOR_INVALID")
		}
		total += p.Bytes
		if total > 128<<20 {
			return nil, errors.New("OWNERSHIP_ARCHIVE_WINDOW_LIMIT")
		}
		w.index[key] = i
	}
	return w, nil
}

func (w *archiveObjectWindow) object(ctx context.Context, reg portfolio.DecisionOwnershipArchiveRegistration, pin portfolio.DecisionOwnershipArchiveObjectPin) (provider.BillingObject, error) {
	var none provider.BillingObject
	if w == nil || w.lookup == nil || w.read == nil || w.write == nil || ctx.Err() != nil {
		return none, errors.New("OWNERSHIP_ARCHIVE_WINDOW_UNAVAILABLE")
	}
	w.active = -1
	i, found := w.index[pin.Key+"\x00"+pin.VersionID]
	if !found || portfolio.Hash(w.pins[i]) != portfolio.Hash(pin) {
		return none, errors.New("OWNERSHIP_ARCHIVE_WINDOW_SELECTOR_CHANGED")
	}
	binding := portfolio.Hash(reg) + reg.IssuedDocumentSHA256
	if w.binding != "" && w.binding != binding {
		return none, errors.New("OWNERSHIP_ARCHIVE_WINDOW_SOURCE_CHANGED")
	}
	start := i / archiveObjectWindowSize * archiveObjectWindowSize
	if start != w.start {
		end := start + archiveObjectWindowSize
		if end > len(w.pins) {
			end = len(w.pins)
		}
		values := make([]archiveWindowObject, end-start)
		// ReplayCache is deliberately sequential and remains bounded at128 rows.
		// Four divides128, so a window never invalidates a cached replay page.
		for n, p := range w.pins[start:end] {
			if !strings.HasPrefix(p.Key, reg.Prefix) || reg.Prefix == "" {
				return none, errors.New("OWNERSHIP_ARCHIVE_WINDOW_PREFIX_CHANGED")
			}
			value, cached, err := w.lookup(ctx, reg, p)
			if err != nil {
				return none, err
			}
			values[n] = archiveWindowObject{pin: p, value: value, cached: cached}
		}
		batch, cancel := context.WithCancel(ctx)
		var pending sync.WaitGroup
		for n := range values {
			if values[n].cached {
				continue
			}
			pending.Add(1)
			go func(n int) {
				defer pending.Done()
				v := &values[n]
				v.value, v.err = w.read(batch, reg, v.pin)
				if v.err == nil && (v.value.Key != v.pin.Key || v.value.VersionID != v.pin.VersionID || int64(len(v.value.Data)) != v.pin.Bytes || source.BytesHash(v.value.Data) != v.pin.SHA256) {
					v.err = errors.New("OWNERSHIP_ARCHIVE_WINDOW_NATIVE_VERSION_CHANGED")
				}
				if v.err == nil {
					// This is raw evidence only. No receipt or aggregate is issued
					// until the unchanged verifier and SQL guards accept this object.
					v.mirror, v.err = w.write(batch, reg.TenantID, reg.ID, v.value.Data)
					if v.err == nil && (model.String(v.mirror, "body_sha256") != v.pin.SHA256 || model.String(v.mirror, "version_id") == "" || model.String(v.mirror, "version_id") == "null") {
						v.err = errors.New("OWNERSHIP_ARCHIVE_WINDOW_READBACK_CHANGED")
					}
				}
				if v.err != nil {
					cancel()
				}
			}(n)
		}
		pending.Wait()
		cancel()
		if err := ctx.Err(); err != nil {
			return none, err
		}
		for _, v := range values {
			if v.err != nil {
				return none, v.err
			}
		}
		w.start, w.values, w.binding = start, values, binding
		w.tenant, w.source = reg.TenantID, reg.ID
	}
	w.active = i - w.start
	return w.values[w.active].value, nil
}

// Return only the exact write+version-readback completed for the current
// verified object. The original repository still rechecks current authority,
// handles concurrent/replayed rows and executes every immutable SQL guard.
func (w *archiveObjectWindow) mirror(ctx context.Context, tenant, id string, raw []byte) (model.Document, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if w == nil || w.active < 0 || w.active >= len(w.values) || w.tenant != tenant || w.source != id {
		return nil, errors.New("OWNERSHIP_ARCHIVE_WINDOW_READBACK_REQUIRED")
	}
	v := w.values[w.active]
	if v.cached || v.err != nil || v.mirror == nil || !bytes.Equal(v.value.Data, raw) || model.String(v.mirror, "body_sha256") != source.BytesHash(raw) || !strings.HasPrefix(model.String(v.mirror, "key"), "tenant/"+tenant+"/commitment-ownership-archive/"+id+"/") {
		return nil, errors.New("OWNERSHIP_ARCHIVE_WINDOW_READBACK_REQUIRED")
	}
	return v.mirror, nil
}

type archiveWindowReader struct {
	*OwnershipArchiveAWSReader
	window *archiveObjectWindow
}

func (r archiveWindowReader) ArchiveObject(ctx context.Context, reg portfolio.DecisionOwnershipArchiveRegistration, pin portfolio.DecisionOwnershipArchiveObjectPin) (provider.BillingObject, error) {
	return r.window.object(ctx, reg, pin)
}
