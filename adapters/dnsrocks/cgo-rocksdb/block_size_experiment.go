package rocksdb

/*
#cgo pkg-config: "rocksdb"
#include "rocksdb/c.h"
*/
import "C"

// SetBlockSize sets the native block-based table target using the official API.
func (options *Options) SetBlockSize(bytes uint64) {
	if options.blockBasedOptions == nil {
		options.blockBasedOptions = NewBlockBasedOptions()
	}
	C.rocksdb_block_based_options_set_block_size(options.blockBasedOptions.cBlockBasedOptions, C.size_t(bytes))
	C.rocksdb_options_set_block_based_table_factory(options.cOptions, options.blockBasedOptions.cBlockBasedOptions)
}
