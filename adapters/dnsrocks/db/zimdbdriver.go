package db

import (
	"encoding/binary"
	"github.com/facebook/dns/dnsrocks/internal/zimnative"
	"github.com/miekg/dns"
	"io"
	"net"
	"sync"
)

type qcRows struct {
	records []zimnative.Record
	exists  bool
}
type qcKey struct {
	owner, kinds string
	wild         bool
}
type qcContext struct {
	rows  map[qcKey]qcRows
	flags map[string]uint32
}

func (c *qcContext) Reset() { clear(c.rows); clear(c.flags) }

type zimdbdriver struct {
	native   *zimnative.Reader
	contexts sync.Pool
}

func openZimDB(path string) (DBI, error) {
	reader, e := zimnative.Open(path)
	if e != nil {
		return nil, e
	}
	return &zimdbdriver{native: reader, contexts: sync.Pool{New: func() any { return &qcContext{} }}}, nil
}
func (z *zimdbdriver) NewContext() Context                                    { return z.contexts.Get().(*qcContext) }
func (z *zimdbdriver) FreeContext(c Context)                                  { c.Reset(); z.contexts.Put(c) }
func (z *zimdbdriver) Close() error                                           { return z.native.Close() }
func (z *zimdbdriver) Reload(path string) (DBI, error)                        { return openZimDB(path) }
func (z *zimdbdriver) GetStats() map[string]int64                             { return map[string]int64{} }
func (z *zimdbdriver) ClosestKeyFinder() ClosestKeyFinder                     { return nil }
func (z *zimdbdriver) FindMap(domain, kind []byte, c Context) ([]byte, error) { return nil, nil }
func (z *zimdbdriver) GetLocationByMap(network *net.IPNet, mapID []byte, c Context) ([]byte, uint8, error) {
	return nil, 0, nil
}
func validQCKey(key []byte) bool { return len(key) >= 3 && key[0] == 0 && key[1] == 0 }
func (z *zimdbdriver) inspect(key []byte, c Context) (uint32, error) {
	if !validQCKey(key) {
		return 0, nil
	}
	ctx := c.(*qcContext)
	if ctx.flags == nil {
		ctx.flags = make(map[string]uint32)
	}
	name := string(key)
	if flags, ok := ctx.flags[name]; ok {
		return flags, nil
	}
	flags, e := z.native.InspectWire(key[2:], false)
	if e == nil {
		ctx.flags[name] = flags
	}
	return flags, e
}
func (z *zimdbdriver) owner(key []byte, types []uint16, wild bool, c Context) (qcRows, error) {
	if !validQCKey(key) {
		return qcRows{}, nil
	}
	ctx := c.(*qcContext)
	if ctx.rows == nil {
		ctx.rows = make(map[qcKey]qcRows)
	}
	kinds := make([]byte, 2*len(types))
	for i, t := range types {
		binary.BigEndian.PutUint16(kinds[2*i:], t)
	}
	cacheKey := qcKey{string(key), string(kinds), wild}
	if rows, ok := ctx.rows[cacheKey]; ok {
		return rows, nil
	}
	rows, exists, e := z.native.LookupWire(key[2:], types, wild)
	if e != nil {
		return qcRows{}, e
	}
	value := qcRows{rows, exists}
	ctx.rows[cacheKey] = value
	return value, nil
}
func qcRow(rr zimnative.Record, wild bool) []byte {
	row := make([]byte, 15, 19+len(rr.Rdata))
	binary.BigEndian.PutUint16(row, rr.Type)
	row[2] = '='
	if wild {
		row[2] = '*'
	}
	binary.BigEndian.PutUint32(row[3:7], rr.TTL)
	if rr.Type == dns.TypeA || rr.Type == dns.TypeAAAA {
		row = binary.BigEndian.AppendUint32(row, 1)
	}
	return append(row, rr.Rdata...)
}
func (z *zimdbdriver) Authority(key []byte, c Context) (bool, bool, error) {
	flags, e := z.inspect(key, c)
	return flags&4 != 0, flags&8 != 0, e
}
func (z *zimdbdriver) Find(key []byte, c Context) ([]byte, error) {
	rows, e := z.owner(key, nil, false, c)
	if e != nil {
		return nil, e
	}
	if len(rows.records) == 0 {
		return nil, io.EOF
	}
	return qcRow(rows.records[0], false), nil
}
func (z *zimdbdriver) ForEach(key []byte, f func([]byte) error, c Context) error {
	for _, wild := range []bool{false, true} {
		if _, e := z.ForEachTypes(key, nil, wild, f, c); e != nil {
			return e
		}
	}
	return nil
}
func (z *zimdbdriver) ForEachTypes(key []byte, types []uint16, wild bool, f func([]byte) error, c Context) (bool, error) {
	rows, e := z.owner(key, types, wild, c)
	if e != nil {
		return false, e
	}
	for _, r := range rows.records {
		value := qcRow(r, wild)
		for n := uint64(0); n < r.Multiplicity; n++ {
			if e = f(value); e != nil {
				return rows.exists, e
			}
		}
	}
	return rows.exists, nil
}
func (z *zimdbdriver) WildcardBoundary(key []byte, c Context) (bool, error) {
	flags, e := z.inspect(key, c)
	return flags&3 != 0, e
}
