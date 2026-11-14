package zimnative

/*
#cgo CXXFLAGS: -O3 -std=c++17 -Wno-deprecated-declarations
#cgo LDFLAGS: -lldns -llz4 -lzstd -lcrypto -lstdc++ -lpthread
#include "bridge.h"
#include <stdlib.h>
*/
import "C"
import (
	"encoding/binary"
	"fmt"
	"sync"
	"unsafe"
)

type Reader struct {
	mu     sync.Mutex
	native unsafe.Pointer
	origin string
}
type Record struct {
	Type         uint16
	TTL          uint32
	Multiplicity uint64
	Rdata        []byte
}

func Open(path string) (*Reader, error) {
	name := C.CString(path)
	defer C.free(unsafe.Pointer(name))
	h := C.zim_open(name)
	if h == nil {
		return nil, fmt.Errorf("ZimDB open failed")
	}
	return &Reader{native: h, origin: C.GoString(C.zim_origin(h))}, nil
}
func (r *Reader) InspectWire(wire []byte, wild bool) (uint32, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.native == nil || len(wire) == 0 {
		return 0, fmt.Errorf("closed reader or empty owner")
	}
	w := C.int(0)
	if wild {
		w = 1
	}
	flags := C.zim_inspect_wire(r.native, (*C.uchar)(unsafe.Pointer(&wire[0])), C.size_t(len(wire)), w)
	if flags < 0 {
		return 0, fmt.Errorf("ZimDB inspect failed")
	}
	return uint32(flags), nil
}
func (r *Reader) LookupWire(wire []byte, types []uint16, wild bool) ([]Record, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.native == nil || len(wire) == 0 {
		return nil, false, fmt.Errorf("closed reader or empty owner")
	}
	w := C.int(0)
	if wild {
		w = 1
	}
	var kinds *C.uint16_t
	if len(types) > 0 {
		kinds = (*C.uint16_t)(unsafe.Pointer(&types[0]))
	}
	var n C.size_t
	var found C.int
	p := C.zim_lookup_wire(r.native, (*C.uchar)(unsafe.Pointer(&wire[0])), C.size_t(len(wire)), w, kinds, C.size_t(len(types)), &n, &found)
	if p == nil {
		return nil, false, fmt.Errorf("ZimDB typed lookup failed")
	}
	defer C.free(unsafe.Pointer(p))
	if uint64(n) > 1<<31-1 {
		return nil, false, fmt.Errorf("oversized owner")
	}
	data := C.GoBytes(unsafe.Pointer(p), C.int(n))
	rows := make([]Record, 0, 4)
	for len(data) > 0 {
		if len(data) < 18 {
			return nil, false, fmt.Errorf("short row")
		}
		size := int(binary.BigEndian.Uint32(data[14:18]))
		if size > len(data)-18 {
			return nil, false, fmt.Errorf("short RDATA")
		}
		rows = append(rows, Record{binary.BigEndian.Uint16(data[:2]), binary.BigEndian.Uint32(data[2:6]), binary.BigEndian.Uint64(data[6:14]), data[18 : 18+size]})
		data = data[18+size:]
	}
	return rows, found != 0, nil
}
func (r *Reader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.native != nil {
		C.zim_close(r.native)
		r.native = nil
	}
	return nil
}
