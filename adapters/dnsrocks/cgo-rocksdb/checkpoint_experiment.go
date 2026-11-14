// Experiment wrapper for RocksDB's native checkpoint C API.
package rocksdb

/*
#cgo pkg-config: "rocksdb"
#include "rocksdb/c.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"unsafe"
)

// CreateCheckpoint preserves a consistent native snapshot and permits shared SSTs.
// A zero log-size threshold asks RocksDB to flush pending memtables first.
func (db *RocksDB) CreateCheckpoint(path string) error {
	var cError *C.char
	checkpoint := C.rocksdb_checkpoint_object_create(db.cDB, &cError)
	if cError != nil {
		defer C.rocksdb_free(unsafe.Pointer(cError))
		return errors.New(C.GoString(cError))
	}
	defer C.rocksdb_checkpoint_object_destroy(checkpoint)
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	C.rocksdb_checkpoint_create(checkpoint, cPath, C.uint64_t(0), &cError)
	if cError != nil {
		defer C.rocksdb_free(unsafe.Pointer(cError))
		return errors.New(C.GoString(cError))
	}
	return nil
}
