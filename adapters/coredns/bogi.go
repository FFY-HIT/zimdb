package bogi

/*
#cgo CFLAGS: -I${SRCDIR}/../../../libbogi23/include
#cgo LDFLAGS: -L${SRCDIR}/../../../libbogi23/build -lbogi23 -Wl,-rpath,${SRCDIR}/../../../libbogi23/build
#include "bogi23_reader.h"
#include "bogi23_dig.h"
#include "bogi23_export.h"
#include <stdlib.h>

static size_t bogi_go_rr_count(Bogi23OwnerGroup *g) {
	if (!g || g->count == 0) return 0;
	return g->sets[0].rdata_count;
}
static const char *bogi_go_rr_type(Bogi23OwnerGroup *g) {
	if (!g || g->count == 0) return "";
	return g->sets[0].rrtype ? g->sets[0].rrtype : "";
}
static uint64_t bogi_go_rr_ttl(Bogi23OwnerGroup *g) {
	if (!g || g->count == 0) return 0;
	return g->sets[0].ttl;
}
static const char *bogi_go_rr_rdata(Bogi23OwnerGroup *g, size_t i) {
	if (!g || g->count == 0 || i >= g->sets[0].rdata_count || !g->sets[0].rdatas)
		return NULL;
	return g->sets[0].rdatas[i];
}
*/
import "C"

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"unsafe"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/file"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("bogi")

// Bogi: Dig-mmap zone backend (Model B / R027).
type Bogi struct {
	Next   plugin.Handler
	path   string
	origin string
	reader *C.Bogi23Reader
	zone   *file.Zone
	mu     sync.Mutex
	depth  int
	seen   map[string]struct{} // owner|TYPE already hydrated
}

func init() { plugin.Register("bogi", setup) }

func setup(c *caddy.Controller) error {
	b := &Bogi{seen: map[string]struct{}{}}
	for c.Next() {
		if !c.NextArg() {
			return c.ArgErr()
		}
		b.path = c.Val()
		origins := plugin.OriginsFromArgsOrServerBlock(c.RemainingArgs(), c.ServerBlockKeys)
		if len(origins) == 0 {
			return c.Err("bogi: missing zone origin")
		}
		b.origin = dns.Fqdn(origins[0])
		for c.NextBlock() {
			return c.Errf("unknown property '%s'", c.Val())
		}
	}

	b.reader = (*C.Bogi23Reader)(C.calloc(1, C.size_t(unsafe.Sizeof(C.Bogi23Reader{}))))
	if b.reader == nil {
		return plugin.Error("bogi", fmt.Errorf("calloc reader failed"))
	}
	cpath := C.CString(b.path)
	rc := C.bogi23_open(b.reader, cpath)
	C.free(unsafe.Pointer(cpath))
	if rc != 0 {
		C.free(unsafe.Pointer(b.reader))
		b.reader = nil
		return plugin.Error("bogi", fmt.Errorf("bogi23_open %s failed", b.path))
	}

	b.zone = file.NewZone(b.origin, b.path)
	if err := b.seedApex(); err != nil {
		C.bogi23_close(b.reader)
		C.free(unsafe.Pointer(b.reader))
		b.reader = nil
		return plugin.Error("bogi", err)
	}
	log.Infof("Dig-direct seed OK zone=%s file=%s", b.origin, b.path)

	c.OnShutdown(func() error {
		if b.reader != nil {
			C.bogi23_close(b.reader)
			C.free(unsafe.Pointer(b.reader))
			b.reader = nil
		}
		return nil
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		b.Next = next
		return b
	})
	return nil
}

func (b *Bogi) Name() string { return "bogi" }

func (b *Bogi) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qname := state.Name()
	if !plugin.Name(b.origin).Matches(qname) {
		return plugin.NextOrFailure(b.Name(), b.Next, ctx, w, r)
	}
	if state.QType() == dns.TypeAXFR || state.QType() == dns.TypeIXFR {
		return dns.RcodeRefused, nil
	}

	b.lazyEnsure(qname, state.QType())

	answer, ns, extra, result := b.zone.Lookup(ctx, state, qname)
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Answer, m.Ns, m.Extra = answer, ns, extra
	switch result {
	case file.Success, file.NoData:
	case file.NameError:
		m.Rcode = dns.RcodeNameError
	case file.Delegation:
		m.Authoritative = false
	case file.ServerFailure:
		if len(m.Answer) == 0 {
			return dns.RcodeServerFailure, nil
		}
		m.Rcode = dns.RcodeServerFailure
	}
	_ = w.WriteMsg(m)
	b.releaseHydrate()
	return dns.RcodeSuccess, nil
}

func (b *Bogi) seedApex() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.depth++
	defer func() { b.depth-- }()
	if err := b.hydrateType(b.origin, "SOA"); err != nil {
		return fmt.Errorf("seed SOA: %w", err)
	}
	if err := b.hydrateType(b.origin, "NS"); err != nil {
		return fmt.Errorf("seed NS: %w", err)
	}
	if b.zone.Apex.SOA == nil {
		return fmt.Errorf("seed: no SOA after Dig for %s", b.origin)
	}
	return nil
}


// releaseHydrate drops query-scoped inserts; Dig remains the data source (R031).
func (b *Bogi) releaseHydrate() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.reader == nil {
		return
	}
	b.depth++
	defer func() { b.depth-- }()
	b.zone = file.NewZone(b.origin, "")
	b.seen = map[string]struct{}{}
	if err := b.hydrateType(b.origin, "SOA"); err != nil {
		log.Warningf("Dig-direct re-seed SOA: %v", err)
		return
	}
	if err := b.hydrateType(b.origin, "NS"); err != nil {
		log.Warningf("Dig-direct re-seed NS: %v", err)
	}
}

func (b *Bogi) lazyEnsure(qname string, qtype uint16) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.depth > 0 || b.reader == nil {
		return
	}
	b.depth++
	defer func() { b.depth-- }()

	name := dns.Fqdn(strings.ToLower(qname))
	b.hydrateAncestorsNS(name)

	kind, _ := b.digLookup(name)
	if kind != C.BOGI23_DIG_EXACT {
		return
	}
	types := []string{"A", "AAAA", "NS", "CNAME", "MX", "TXT", "SOA"}
	if t := typeString(qtype); t != "" {
		types = append([]string{t}, types...)
	}
	seen := map[string]struct{}{}
	for _, t := range types {
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		_ = b.hydrateType(name, t)
	}
}

func (b *Bogi) hydrateAncestorsNS(name string) {
	cur := name
	for {
		if cur == b.origin || strings.HasSuffix(cur, "."+b.origin) {
			_ = b.hydrateType(cur, "NS")
		}
		if cur == b.origin || cur == "." {
			break
		}
		i := strings.IndexByte(cur, '.')
		if i < 0 {
			break
		}
		cur = cur[i+1:]
	}
}

func (b *Bogi) digLookup(name string) (C.Bogi23DigLookupKind, string) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var kind C.Bogi23DigLookupKind
	var succ [512]C.char
	if C.bogi23_dig_lookup(b.reader, cname, &kind, &succ[0], 512) != 0 {
		return C.BOGI23_DIG_NONE, ""
	}
	return kind, C.GoString(&succ[0])
}

func (b *Bogi) hydrateType(owner, rrtype string) error {
	key := owner + "|" + rrtype
	if _, ok := b.seen[key]; ok {
		return nil
	}

	cowner := C.CString(owner)
	ctype := C.CString(rrtype)
	defer C.free(unsafe.Pointer(cowner))
	defer C.free(unsafe.Pointer(ctype))

	var group C.Bogi23OwnerGroup
	var found C.int
	if C.bogi23_dig_get_rrset(b.reader, cowner, ctype, &group, &found) != 0 {
		return fmt.Errorf("GetRRset failed")
	}
	defer C.bogi23_free_group(b.reader, &group)
	if found == 0 {
		b.seen[key] = struct{}{}
		return nil
	}
	n := int(C.bogi_go_rr_count(&group))
	if n == 0 {
		b.seen[key] = struct{}{}
		return nil
	}
	ttl := uint32(C.bogi_go_rr_ttl(&group))
	rtype := C.GoString(C.bogi_go_rr_type(&group))
	for i := 0; i < n; i++ {
		crd := C.bogi_go_rr_rdata(&group, C.size_t(i))
		if crd == nil {
			continue
		}
		rd := C.GoString(crd)
		line := fmt.Sprintf("%s %d IN %s %s", owner, ttl, rtype, rd)
		rr, err := dns.NewRR(line)
		if err != nil {
			return fmt.Errorf("parse %q: %w", line, err)
		}
		b.zone.Lock()
		ierr := b.zone.Insert(rr)
		b.zone.Unlock()
		if ierr != nil {
			return ierr
		}
	}
	b.seen[key] = struct{}{}
	return nil
}

func typeString(t uint16) string {
	if s, ok := dns.TypeToString[t]; ok {
		return s
	}
	return ""
}
