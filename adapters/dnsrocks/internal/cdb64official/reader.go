// Package cdb64official is a thin binding to DJB's public-domain CDB64 20251021 reader.
// It requires the official mmap path so independent query contexts never share a seek offset.
package cdb64official

/*
#cgo CFLAGS: -DCDB64
#include "cdb.h"
*/
import "C"

import (
    "fmt"
    "io"
    "os"
    "runtime"
    "unsafe"
)

type Cdb struct {
    native C.struct_cdb64
    file *os.File
}

type Context struct { native C.struct_cdb64 }

func NewContext() *Context { return &Context{} }
func (c *Context) Reset() { c.native = C.struct_cdb64{} }

func Open(path string) (*Cdb, error) {
    f, err := os.Open(path)
    if err != nil { return nil, err }
    info, err := f.Stat()
    if err != nil || info.Size() < 4096 {
        f.Close()
        return nil, fmt.Errorf("CDB64: invalid file header/size: %v", err)
    }
    db := &Cdb{file: f}
    C.cdb64_init(&db.native, C.num(f.Fd()))
    if db.native._map == nil {
        f.Close()
        return nil, fmt.Errorf("CDB64: official reader could not mmap %s", path)
    }
    return db, nil
}

func (db *Cdb) Close() error {
    C.cdb64_free(&db.native)
    return db.file.Close()
}

func (db *Cdb) FindStart(ctx *Context) {
    ctx.native = db.native
    C.cdb64_findstart(&ctx.native)
}

func (db *Cdb) FindNext(key []byte, ctx *Context) ([]byte, error) {
    var data *C.char
    if len(key) > 0 { data = (*C.char)(unsafe.Pointer(&key[0])) }
    found, err := C.cdb64_findnext(&ctx.native, data, C.num(len(key)))
    runtime.KeepAlive(key)
    if found < 0 { return nil, fmt.Errorf("CDB64 findnext: %v", err) }
    if found == 0 { return nil, io.EOF }
    length, offset := int64(ctx.native.dlen), int64(ctx.native.dpos)
    size := int64(ctx.native.size)
    if length < 0 || length > (1<<31)-1 || offset < 0 || offset > size || length > size-offset {
        return nil, fmt.Errorf("CDB64: invalid DNS row bounds")
    }
    return C.GoBytes(unsafe.Add(unsafe.Pointer(ctx.native._map), offset), C.int(length)), nil
}
